package com.ysoft.security.odc.dotnet;

import java.util.Collections;
import java.util.Map;

public final class DAVulnerableDependency {

    private final String name;

    private final String version;

    private final Map<String, DAVulnerability> vulnerabilities;

    public DAVulnerableDependency(String name, String version, Map<String, DAVulnerability> vulnerabilities) {
        this.name = name;
        this.version = version;
        this.vulnerabilities = vulnerabilities;
    }

    public String getName() {
        return name;
    }

    public Map<String, DAVulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public String getVersion() {
        return version;
    }

    public String getKey() {
        return getName() + ":" + getVersion();
    }

    public static DAVulnerableDependency withNoVulnerability(String identifier) {
        final String[] parts = identifier.split(":");
        if(parts.length != 2){
            throw new IllegalArgumentException("Identifier is expected to contain exactly one colon: "+identifier);
        }
        return new DAVulnerableDependency(parts[0], parts[1], Collections.emptyMap());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        DAVulnerableDependency that = (DAVulnerableDependency) o;

        if (!name.equals(that.name)) return false;
        if (!version.equals(that.version)) return false;
        return vulnerabilities.equals(that.vulnerabilities);
    }

    @Override
    public int hashCode() {
        int result = name.hashCode();
        result = 31 * result + version.hashCode();
        result = 31 * result + vulnerabilities.hashCode();
        return result;
    }
}
