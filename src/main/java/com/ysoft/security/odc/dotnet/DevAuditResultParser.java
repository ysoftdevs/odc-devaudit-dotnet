package com.ysoft.security.odc.dotnet;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.Character.isDigit;
import static java.util.Collections.unmodifiableMap;

/**
 * Parsers for DevAudit results. It is expected that -n is passed to DevAudit. If it is not the case, DevAudit might
 * provide results that are not parseable by this class.
 */
public class DevAuditResultParser {

    private static final Pattern VULNERABLE_PATTERN = Pattern.compile(
            "\\[[0-9]+/[0-9]+\\] ([^ ]+) \\[VULNERABLE\\] +[0-9]+ known vulnerabilit.*affecting installed package version\\(s\\): \\[([^, ]+)\\]$"
    );

    private static final Pattern NON_VULNERABLE_PATTERN = Pattern.compile(
            "\\[[0-9]+/[0-9]+\\] ([^ ]+) (no known vulnerabilities\\.|[0-9]+ known vulnerabilit(y|ies), 0 affecting installed package version\\(s\\)\\.)$"
    );

    // --[1/3] [CVE-2011-4969]  Improper Neutralization of Input During Web Page Generation ("Cross-site Scripting")
    private static final Pattern CVE_VULNERABILITY_START_PATTERN = Pattern.compile("--\\[[0-9]+/[0-9]+\\] \\[(CVE-[0-9]{4}-[0-9]+)\\] (.*)$");

    // --[2/3] Cross Site Scripting (XSS)
    private static final Pattern VULNERABILITY_START_PATTERN = Pattern.compile("--\\[[0-9]+/[0-9]+\\] (.*)$");
    public static final String BANNER_FIRST_LINE = " _____                 _______            __  __  __   ";

    public static Map<String, DAVulnerableDependency> parse(BufferedReader in) throws IOException {
        //final String version = consumeHeaderWithVersion(in);
        consumeLog(in);
        expectLine(in, "Package Source Audit Results");
        expectLine(in, "============================");
        expectLineRegex(in, "^([0-9]+ total vulnerabilities|1 total vulnerability) found in NuGet package source audit. Total time for audit: [0-9]+ ms.");
        expectLine(in, "");
        final Map<String, DAVulnerableDependency> out = consumeVulnerableDependencies(in);
        if(out.isEmpty()){
            // When there is no vulnerability, there is also no footer
            final String line = in.readLine();
            if(line != null){
                throw new UnexpectedFormatException("Expected EOF when there is no vulnerability.");
            }
        }else{
            consumeFooter(in);
        }
        return out;
    }

    private static void consumeBanner(BufferedReader in) throws IOException {
        expectLine(in, BANNER_FIRST_LINE);
        consumeRestOfBanner(in);
    }

    private static void consumeRestOfBanner(BufferedReader in) throws IOException {
        expectLine(in, "|     \\ .-----..--.--.|   _   |.--.--..--|  ||__||  |_ ");
        expectLine(in, "|  --  ||  -__||  |  ||       ||  |  ||  _  ||  ||   _|");
        expectLine(in, "|_____/ |_____| \\___/ |___|___||_____||_____||__||____|");
        expectLine(in, "                                                       ");
        expectLine(in, "");
    }

    private static Map<String, DAVulnerableDependency> consumeVulnerableDependencies(BufferedReader in) throws IOException {
        final Map<String, DAVulnerableDependency> result = new HashMap<>();
        Optional<Optional<DAVulnerableDependency>> maybeVulnerableDependency;
        while ( (maybeVulnerableDependency = consumeDependencyInfo(in)).isPresent()){
            if(maybeVulnerableDependency.get().isPresent()){
                final DAVulnerableDependency vulnerableDependency = maybeVulnerableDependency.get().get();
                final String key = vulnerableDependency.getKey();
                if(result.containsKey(key) && !result.get(key).equals(vulnerableDependency)){
                    throw new UnexpectedFormatException("Vulnerable dependency with the following key is there twice with a different result: "+key);
                }
                result.put(key, vulnerableDependency);
            }
        }
        return unmodifiableMap(result);
    }

    private static Optional<Optional<DAVulnerableDependency>> consumeDependencyInfo(BufferedReader in) throws IOException {
        /* Now, I am expecting either line like this:
        [11/17] jQuery.Validation [VULNERABLE]  1 known vulnerabilities,  1 affecting installed package version(s): [1.6.0]
        or like this:
        [12/17] AntiXSS 1 known vulnerability, 0 affecting installed package version(s).
        or an empty line (end)
         */
        final String headerLine = in.readLine();
        if(headerLine.equals("")){
            return Optional.empty();
        }else{
            final Matcher vulnerableMatcher = VULNERABLE_PATTERN.matcher(headerLine);
            if(vulnerableMatcher.matches()){
                final String name = vulnerableMatcher.group(1);
                final String version = vulnerableMatcher.group(2);
                final DAVulnerableDependency vd = consumeVulnerableDependencyInfo(in, name, version);
                return Optional.of(Optional.of(vd));
            } else {
                final Matcher nonVulnerableMatcher = NON_VULNERABLE_PATTERN.matcher(headerLine);
                if(nonVulnerableMatcher.matches()){
                    return Optional.of(Optional.empty());
                } else {
                    throw new UnexpectedFormatException("Expected dependency header, found: "+headerLine);
                }
            }
        }
    }

    private static DAVulnerableDependency consumeVulnerableDependencyInfo(BufferedReader in, String name, String version) throws IOException {
        final VulnerabilitiesParser vulnerabilitiesParser = new VulnerabilitiesParser();
        String line;
        while(!(line = in.readLine()).equals("")){
            vulnerabilitiesParser.push(line);
        }
        return new DAVulnerableDependency(name, version, vulnerabilitiesParser.finish());
    }

    private static void consumeFooter(BufferedReader in) throws IOException {
        expectLine(in, "Vulnerabilities Data Providers");
        expectLine(in, "==============================");
        expectLine(in, "");
        //noinspection StatementWithEmptyBody
        while( in.readLine() != null) {
        }
    }

    private static void expectLine(BufferedReader in, String expectedLine) throws IOException {
        final String line = in.readLine();
        if(line == null){
            throw new UnexpectedFormatException("Expected '"+expectedLine+"', got EOF");
        }
        if(!line.equals(expectedLine)){
            throw new UnexpectedFormatException("Expected '"+expectedLine+"', got: "+line);
        }
    }

    private static void expectLineRegex(BufferedReader in, String regex) throws IOException {
        final String line = in.readLine();
        if(line == null){
            throw new UnexpectedFormatException("Expected something that matches '"+regex+"', got EOF");
        }
        if(!line.matches(regex)){
            throw new UnexpectedFormatException("Expected something that matches '"+regex+"', got: "+line);
        }
    }


    private static void consumeLog(BufferedReader in) throws IOException {
        String line;
        while( (line = in.readLine()) != null){
            if(line.equals(" ") || line.equals("")){
                return;
            }else if(line.equals(BANNER_FIRST_LINE)){
                consumeRestOfBanner(in);
            }else{
                if(line.toLowerCase().contains("[error]")){
                    if(isInnocentErrorMessage(line)){
                        System.out.println("Ignoring error message: "+line);
                    }else{
                        final StringBuilder messageBuilder = new StringBuilder(line);
                        while( (line = in.readLine()) != null){
                            messageBuilder.append(line);
                            messageBuilder.append('\n');
                        }
                        throw new IOException("Error when running DevAudit: "+messageBuilder.toString());
                    }
                }
                System.out.println("log: "+line);
            }
        }
        throw new UnexpectedFormatException("Reached EOF before finding end of log");
    }

    private static boolean isInnocentErrorMessage(String line) {
        final int firstSpacePos = line.indexOf(' ');
        if(firstSpacePos == -1){
            return false;
        }
        final String bareErrorMessage = line.substring(firstSpacePos + 1);
        return bareErrorMessage.equals("[AUDIT] [ERROR] GetOSName() failed.");
    }

    private static String consumeHeaderWithVersion(BufferedReader in) throws IOException {
        String line;
        while( (line = in.readLine()) != null){
            if(line.startsWith("v")){
                return line.substring(1);
            }
        }
        throw new UnexpectedFormatException("Reached EOF before finding DevAudit version");
    }


    private static class VulnerabilitiesParser {
        private final Map<String, DAVulnerability> vulnerabilities = new HashMap<>();
        private VulnerabilityParser vulnerabilityParser;

        public void push(String line) throws UnexpectedFormatException {
            if(line.startsWith("--")){
                finishOldVulnerability();
                // new vulnerability
                final Optional<String> cve;
                final String title;
                final Matcher cveVulnerabilityMatcher = CVE_VULNERABILITY_START_PATTERN.matcher(line);
                if(cveVulnerabilityMatcher.matches()){
                    cve = Optional.of(cveVulnerabilityMatcher.group(1));
                    title = cveVulnerabilityMatcher.group(2);
                }else{
                    final Matcher vulnerabilityMatcher = VULNERABILITY_START_PATTERN.matcher(line);
                    if(vulnerabilityMatcher.matches()){
                        title = vulnerabilityMatcher.group(1);
                        cve = Optional.empty();
                    }else{
                        throw new UnexpectedFormatException("Unexpected initial vulnerability line: "+line);
                    }
                }
                vulnerabilityParser = new VulnerabilityParser(title, cve);
            }else{
                vulnerabilityParser.push(line);
            }

        }

        private void finishOldVulnerability() throws UnexpectedFormatException {
            if(vulnerabilityParser != null) {
                final DAVulnerability vulnerability = vulnerabilityParser.build();
                final String key = vulnerability.getIdentifier();
                if (vulnerabilities.containsKey(key)) {
                    throw new UnexpectedFormatException("The following vulnerability is there multiple times: " + vulnerability);
                } else {
                    vulnerabilities.put(key, vulnerability);
                    vulnerabilityParser = null;
                }
            }
        }

        public Map<String, DAVulnerability> finish() throws UnexpectedFormatException {
            finishOldVulnerability();
            return unmodifiableMap(vulnerabilities);
        }

    }

    private static class VulnerabilityParser {
        private final String title;
        private final Optional<String> cve;
        private String lastKey = null;
        private final Map<String, String> data = new HashMap<String, String>();

        public VulnerabilityParser(String title, Optional<String> cve) {
            this.title = title;
            this.cve = cve;
        }

        public DAVulnerability build() {
            final String ossIndexId = data.get("Id");
            final String identifier = cve.orElseGet(() -> "OSSINDEX-"+ossIndexId);
            return new DAVulnerability(
                    title.trim(),
                    identifier,
                    data.get("Description").trim(),
                    data.get("Affected versions").trim(),
                    ossIndexId,
                    data.get("Provided by").trim(),
                    cve
            );
        }

        private void addAffectedVersion(String affectedVersion) {
            if(data.containsKey("Affected versions")){
                data.put("Affected versions", data.get("Affected versions")+", "+affectedVersion);
            }else{
                data.put("Affected versions", affectedVersion);
            }
        }

        public void push(String line) throws UnexpectedFormatException {
            if(line.startsWith("  --")){
                final String[] parts = line.split(":", 2);
                final String key = parts[0].substring(4);
                final String value = parts[1].trim();
                lastKey = key;
                if(data.containsKey(key)){
                    throw new UnexpectedFormatException("Duplicate key for vulnerability: "+key);
                }else{
                    data.put(key, value);
                }
            }else if(line.startsWith("    --") /*4 spaces and 2 minuses*/ || line.startsWith("      "/* 6 spaces*/)){
                // multiline
                data.put(lastKey, data.get(lastKey)+"\n"+line.substring(6));
            }else if(data.containsKey("Description") && !line.equals("") && isDigit(line.charAt(0))){
                // looks like affected version number
                addAffectedVersion(line);
            }else{
                throw new UnexpectedFormatException("Unexpected line start: "+line);
            }
        }
    }

}
