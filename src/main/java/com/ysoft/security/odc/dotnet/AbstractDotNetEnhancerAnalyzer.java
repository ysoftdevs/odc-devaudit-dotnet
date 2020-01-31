package com.ysoft.security.odc.dotnet;

import org.owasp.dependencycheck.analyzer.AbstractFileTypeAnalyzer;

import java.io.FileFilter;

abstract class AbstractDotNetEnhancerAnalyzer extends AbstractFileTypeAnalyzer {

    public static final String DOTNET_ENHANCER_ANALYZER_KEY = "com.ysoft.dotnetEnhancer.enabled";

    protected FileFilter getFileFilter() {
        return f -> f.getName().toLowerCase().endsWith(".dll");
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return DOTNET_ENHANCER_ANALYZER_KEY;
    }

}
