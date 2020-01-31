package com.ysoft.security.odc.dotnet;

import org.apache.commons.compress.utils.Sets;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.AnalysisPhase;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.exception.InitializationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class FalsePositiveWarningAnalyzer extends AbstractDotNetEnhancerAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(FalsePositiveWarningAnalyzer.class);

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {}

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        final List<DevAuditDotNetEnhancerAnalyzer> dotNetEnhancerAnalyzers = engine
                .getAnalyzers(DevAuditDotNetEnhancerAnalyzer.ANALYSIS_PHASE)
                .stream()
                .filter(x -> x instanceof DevAuditDotNetEnhancerAnalyzer)
                .map(x -> (DevAuditDotNetEnhancerAnalyzer)x)
                .collect(Collectors.toList());
        if(dotNetEnhancerAnalyzers.size() != 1){
            throw new AssertionError("Expected exactly one Analyzer, "+dotNetEnhancerAnalyzers.size()+" found.");
        }
        final DevAuditDotNetEnhancerAnalyzer dotNetEnhancerAnalyzer = dotNetEnhancerAnalyzers.get(0);
        try {
            final Map<String, DAVulnerableDependency> resultsForEngine = dotNetEnhancerAnalyzer.getResultsForEngine(engine);
            final Set<String> allVulnerabilityNames = dependency.getVulnerabilities().stream().map(Vulnerability::getName).collect(Collectors.toSet());
            final Set<String> matchedVulnerabilityNames = dotNetEnhancerAnalyzer.findRelevantVulnerabilities(dependency, resultsForEngine).map(DAVulnerability::getIdentifier).collect(Collectors.toSet());
            final Set<String> falsePositiveSuspects = diff(allVulnerabilityNames, matchedVulnerabilityNames);
            if(falsePositiveSuspects.isEmpty()){
                LOGGER.info("No false positive suspect for dependency {}", dependency);
            }else{
                final List<String> falsePositiveSuspectsList = new ArrayList<>(new TreeSet<>(falsePositiveSuspects));
                LOGGER.warn("The following vulnerabilities for {} were not found by DevAudit, so they are suspected as false positive: {}", dependency, falsePositiveSuspectsList);
            }
        } catch (IOException e) {
            throw new AnalysisException(e);
        }

    }

    private <T> Set<T> diff(Set<T> set1, Set<T> set2) {
        final HashSet<T> ts = new HashSet<>(set1);
        ts.removeAll(set2);
        return Collections.unmodifiableSet(ts);
    }

    @Override
    public String getName() {
        return ".NET Analyzer Enhancer – False positive warnings";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.FINAL;
    }
}
