package com.ysoft.security.odc.dotnet;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.collections.map.ReferenceMap;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.AnalysisPhase;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.naming.Identifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.commons.collections.map.AbstractReferenceMap.HARD;
import static org.apache.commons.collections.map.AbstractReferenceMap.SOFT;

enum Mode {
    // The options can be accessed reflectively, so they might look unused
    @SuppressWarnings("unused") CVE_ONLY(true, false),
    @SuppressWarnings("unused") CVE_PREFERRED(true, true),
    @SuppressWarnings("unused") PURE_DA(false, true);

    private final boolean convertCve;
    private final boolean useNonCve;

    Mode(boolean convertCve, boolean useNonCve) {
        this.convertCve = convertCve;
        this.useNonCve = useNonCve;
    }

    public boolean convertCve() {
        return convertCve;
    }

    public boolean useNonCve() {
        return useNonCve;
    }

}

public class DevAuditDotNetEnhancerAnalyzer extends AbstractDotNetEnhancerAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(DevAuditDotNetEnhancerAnalyzer.class);
    static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.FINDING_ANALYSIS;

    private DevAuditRunner devAuditRunner;

    private CveDB cveDB;

    /**
     * Once analysis fails, it never tries it again in order not to spam the OSS Index API and the log
     */
    private boolean failed = false;

    @SuppressWarnings("unchecked")
    private final Map<Engine, Map<String, DAVulnerableDependency>> results = new ReferenceMap(SOFT, HARD);

    /**
     * We do most of the work when called for the first dependency (we can't go parallel at this moment) and then just quickly lookup the results for
     * other dependencies (when parallelism is almost useless). So, parallelism would require some work for synchronizing the initial lookup with low
     * payoff.
     */
    @Override
    public boolean supportsParallelProcessing() {
        return false;
    }

    private Map<String, DAVulnerableDependency> getOrCreateResultsForEngine(Engine engine) throws IOException {
        // Cannot use computeIfAbsent due to checked exceptions… Fsck!
        final Map<String, DAVulnerableDependency> resultIfCached = results.get(engine);
        if (resultIfCached != null) {
            return resultIfCached;
        }
        if (failed) {
            // Don't spam API and log
            throw new RuntimeException("The analyzer " + getName() + " is in failed state. Look for the first error message of this analyzer.");
        }
        try {
            final Map<String, DAVulnerableDependency> result = findVulnerableLibrariesForEngine(engine);
            results.put(engine, result);
            return result;
        } catch (Throwable e) {
            failed = true;
            throw e;
        }
    }

    public Map<String, DAVulnerableDependency> getResultsForEngine(Engine engine) throws IOException {
        final Map<String, DAVulnerableDependency> resultIfCached = results.get(engine);
        if (resultIfCached != null) {
            return resultIfCached;
        } else {
            throw new NoSuchElementException();
        }
    }

    private Map<String, DAVulnerableDependency> findVulnerableLibrariesForEngine(Engine engine) throws IOException {
        final List<String> nugetIdentifiers = Arrays.stream(engine.getDependencies())
                .flatMap(dependency -> dependency.getSoftwareIdentifiers().stream()
                        .filter(identifier -> identifier.getValue().startsWith("pkg:" + DllFindingDotNetEnhancerAnalyzer.DEPENDENCY_TYPE)))
                .map(Identifier::getValue)
                .collect(Collectors.toList());
        final Map<String, DAVulnerableDependency> results = devAuditRunner.run(nugetIdentifiers);
        LOGGER.info("scan results: {}", results);
        return results;
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        devAuditRunner = new DevAuditRunner(Paths.get(getSettings().getString("com.ysoft.dotnetEnhancer.devAuditPath")));
        try {
            cveDB = new CveDB(getSettings());
        } catch (DatabaseException e) {
            throw new InitializationException(e);
        }
    }

    private Mode getMode() {
        return Mode.valueOf(getSettings().getString("com.ysoft.dotnetEnhancer.vulnerabilityMode", "CVE_PREFERRED"));
    }

    @Override
    public String getName() {
        return ".NET Analyzer Enhancer – DevAudit runner";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        try {
            final Map<String, DAVulnerableDependency> resultsForEngine = getOrCreateResultsForEngine(engine);
            LOGGER.info("Scanning Dependency {}", dependency);
            final Stream<DAVulnerability> matchedVulnerabilities = findRelevantVulnerabilities(dependency, resultsForEngine);
            for (final DAVulnerability daVulnerability : matchedVulnerabilities.collect(Collectors.toSet())) {
                convertVulnerability(daVulnerability).ifPresent(dependency::addVulnerability);
            }
        } catch (IOException e) {
            throw new AnalysisException(e);
        }
    }

    Stream<DAVulnerability> findRelevantVulnerabilities(Dependency dependency, Map<String, DAVulnerableDependency> resultsForEngine) {
        final Stream<String> identifiers = dependency.getSoftwareIdentifiers().stream()
                .map(Identifier::getValue)
                .filter(value -> value.startsWith("pkg:" + DllFindingDotNetEnhancerAnalyzer.DEPENDENCY_TYPE))
                .peek(value -> LOGGER.info("Identifier: {}", value));
        final Stream<DAVulnerableDependency> matchedVulnerableDependencies =
                identifiers
                        .map(resultsForEngine::get)
                        .filter(Objects::nonNull)
                        .peek(vulnerableDependency -> LOGGER.info("Vulnerable dependency: {}", vulnerableDependency));
        return matchedVulnerableDependencies
                .flatMap(x -> x.getVulnerabilities().values().stream())
                .peek(vulnerability -> LOGGER.info("Vulnerability: {}", vulnerability));
    }

    private Optional<Vulnerability> convertVulnerability(DAVulnerability daVulnerability) throws AnalysisException {
        final Optional<String> optionalCve = daVulnerability.getOptionalCve();
        if (getMode().convertCve() && optionalCve.isPresent()) {
            final String cve = optionalCve.get();
            try {
                final Vulnerability vulnerability = cveDB.getVulnerability(cve);
                if (vulnerability != null) {
                    return Optional.of(vulnerability);
                } else {
                    LOGGER.warn("Cannot load details for vulnerability {} from ODC DB", cve);
                    // Now, we will continue with other options
                }
            } catch (DatabaseException e) {
                throw new AnalysisException(e);
            }
        }
        // now, we don't have CVE
        if (getMode().useNonCve()) {
            final Vulnerability vulnerability = new Vulnerability();
            vulnerability.setName(daVulnerability.getIdentifier());
            vulnerability.setDescription(daVulnerability.getTitle() + "\n\n" + daVulnerability.getDescription());
            return Optional.of(vulnerability);
        } else {
            LOGGER.warn("Ignoring vulnerability {} because it has no CVE. If you would like to include such vulnerabilities, configure com.ysoft.dotnetEnhancer.vulnerabilityMode accordingly.", daVulnerability.getIdentifier());
            return Optional.empty();
        }
    }

    @Override
    protected void closeAnalyzer() throws Exception {
        cveDB.close();
        super.closeAnalyzer();
    }

}
