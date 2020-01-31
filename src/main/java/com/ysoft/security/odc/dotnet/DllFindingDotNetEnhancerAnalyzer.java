package com.ysoft.security.odc.dotnet;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.AnalysisPhase;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.naming.PurlIdentifier;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

import com.github.packageurl.MalformedPackageURLException;

public class DllFindingDotNetEnhancerAnalyzer extends AbstractDotNetEnhancerAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(DllFindingDotNetEnhancerAnalyzer.class);

    static final String DEPENDENCY_TYPE = "nuget";

    private Connection connection;

    @Override
    public String getName() {
        return ".NET Analyzer Enhancer – finder";
    }

    @Override
    public AnalysisPhase getAnalysisPhase() {
        return AnalysisPhase.IDENTIFIER_ANALYSIS;
    }

    @Override
    protected void prepareFileTypeAnalyzer(Engine engine) throws InitializationException {
        try {
            connection = DriverManager.getConnection(
                    getSettings().getString("com.ysoft.dotnetEnhancer.db.connectionString"),
                    getSettings().getString("com.ysoft.dotnetEnhancer.db.userName"),
                    getSettings().getString("com.ysoft.dotnetEnhancer.db.password")
            );
        } catch (SQLException e) {
            throw new InitializationException("Cannot connect to the Nuget index DB", e);
        }
    }

    @Override
    protected void analyzeDependency(Dependency dependency, Engine engine) throws AnalysisException {
        try {
            final boolean isDotNet = DllAnalyzer.isDotNet(dependency.getActualFile());
            if(!isDotNet){
                // This prevents some noise like msvcr90.dll being identified as UmbracoCMS.
                return;
            }
            final PreparedStatement statement = connection.prepareStatement(
                    "SELECT * FROM nuget_index_hashes WHERE digest_hex_sha1 = ? AND digest_hex_md5 = ?"
            );
            statement.setString(1, dependency.getSha1sum().toUpperCase());
            statement.setString(2, dependency.getMd5sum().toUpperCase());
            final ResultSet resultSet = statement.executeQuery();
            boolean empty = true;
            final Map<String, Integer> versionlessIdentifiersCounts = new HashMap<>();
            final Map<String, Confidence> identifierToConfidence = new HashMap<>();
            while(resultSet.next()){
                empty = false;
                final String name = resultSet.getString("name");
                final String version = resultSet.getString("version");
                assert name.indexOf(':') == -1;
                assert version.indexOf(':') == -1;
                final Confidence confidence = dependency.getFileName().toLowerCase().contains(name.toLowerCase()) ? Confidence.HIGHEST : Confidence.MEDIUM;
                versionlessIdentifiersCounts.merge(name, 1, Integer::sum);
                final String identifier = name+":"+version;
                final Confidence existingConfidence = identifierToConfidence.get(identifier);
                // Insert if it doesn't exist. Override if it exists with a lower confidence. (Use the highest confidence we have.)
                // Note that ordinals are reversed, so I am using the “-” operator
                if( (existingConfidence == null) || (-confidence.ordinal() > -existingConfidence.ordinal()) ){
                    identifierToConfidence.put(identifier, confidence);
                }
            }
            LOGGER.info("Identifier counts: {}", versionlessIdentifiersCounts);
            for (Map.Entry<String, Confidence> identifierEntry : identifierToConfidence.entrySet()) {
                final String fullIdentifier = identifierEntry.getKey();
                final String versionlessIdentifier = fullIdentifier.substring(0, fullIdentifier.indexOf(':'));
                final String version = fullIdentifier.substring(fullIdentifier.indexOf(':') + 1);
                LOGGER.info("Looking for versionless identifier: {}", versionlessIdentifier);
                final boolean hasMultipleOccurences = versionlessIdentifiersCounts.get(versionlessIdentifier) > 1;
                // Make confidence low if it occurs in multiple versions. It is likely some generic bundled library.
                final Confidence confidence = hasMultipleOccurences ? Confidence.LOW : identifierEntry.getValue();
                dependency.addSoftwareIdentifier(new PurlIdentifier(DEPENDENCY_TYPE, versionlessIdentifier, version, confidence));
            }
            //noinspection ConstantConditions because isDotNet is currently always true at this point, but it might change later
            if(empty && isDotNet){
                final String msg = "Unidentified dependency: ("+dependency.getSha1sum()+"-"+dependency.getMd5sum()+") " + dependency;
                if(isStrict()){
                    throw new AnalysisException(msg);
                }else{
                    LOGGER.warn(msg);
                }
            }
        } catch (SQLException | IOException | MalformedPackageURLException e) {
            throw new AnalysisException(e);
        }
    }

    private boolean isStrict() throws InvalidSettingException {
        return getSettings().getBoolean("com.ysoft.dotnetEnhancer.strictSearch", false);
    }

    @Override
    protected void closeAnalyzer() throws Exception {
        try{
            super.closeAnalyzer();
        }finally {
            if(connection != null){
                connection.close();
                connection = null;
            }
        }
    }

}