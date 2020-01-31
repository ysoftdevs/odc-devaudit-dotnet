package com.ysoft.security.odc.dotnet;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static com.google.common.collect.Sets.newHashSet;
import static java.util.Collections.emptyMap;
import static org.junit.Assert.*;

public class DevAuditResultParserTest {

    private final Map<String, DAVulnerableDependency> vulnerableDependencies;

    public DevAuditResultParserTest() throws IOException {
        try(final BufferedReader in = new BufferedReader(new InputStreamReader(getClass().getResourceAsStream("/out.new2.log")))) {
            vulnerableDependencies = DevAuditResultParser.parse(in);
        }
    }

    @Test
    public void testEmptyResult() throws IOException {
        try(final BufferedReader in = new BufferedReader(new InputStreamReader(getClass().getResourceAsStream("/empty.log")))) {
            final Map<String, DAVulnerableDependency> dependencyMap = DevAuditResultParser.parse(in);
            assertEquals(emptyMap(), dependencyMap);
        }

    }

    @Test
    public void testSingleResult() throws IOException {
        try(final BufferedReader in = new BufferedReader(new InputStreamReader(getClass().getResourceAsStream("/single.log")))) {
            final Map<String, DAVulnerableDependency> dependencyMap = DevAuditResultParser.parse(in);
            assertEquals(1, dependencyMap.size());
            assertEquals(newHashSet("LibGit2Sharp:0.20.0"), dependencyMap.keySet());
        }

    }

    @Test
    public void testListOfVulnerableDependencies() {
        assertEquals(newHashSet(
                "Backbone.js:0.3.3",
                "Ember:1.4.0-beta1",
                "jQuery:1.6",
                "jQuery.Migrate:1.1.1",
                "jQuery.UI.Combined:1.9.2",
                "jQuery.Validation:1.6.0",
                "LibGit2Sharp:0.20.0",
                "Microsoft.AspNet.Mvc:5.0.0",
                "Node.js:4.1.1",
                "NServiceBus:3.2.7",
                "Twilio.Mvc:3.2.0",
                "UmbracoCms:6.0.0"
        ), vulnerableDependencies.keySet());
    }

    @Test
    public void testName(){
        assertEquals(
                "UmbracoCms",
                vulnerableDependencies.get("UmbracoCms:6.0.0").getName()
        );
    }

    @Test
    public void testVersion(){
        assertEquals(
                "6.0.0",
                vulnerableDependencies.get("UmbracoCms:6.0.0").getVersion()
        );
    }

    @Test
    public void testVersionWithBeta(){
        assertEquals(
                "1.4.0-beta1",
                vulnerableDependencies.get("Ember:1.4.0-beta1").getVersion()
        );
    }

    @Test
    public void testVulnerabilityList(){
        assertEquals(
                newHashSet(
                        "CVE-2017-15279",
                        "CVE-2017-15280",
                        "OSSINDEX-b23f9aaa-db0a-4eb5-9c57-0eec46017953",
                        "OSSINDEX-91d9b638-bab4-4ca6-aa2e-80ae05aa1f3e",
                        "OSSINDEX-b3f3299b-24d7-4ea0-b9c8-617abca38636",
                        "OSSINDEX-2e8376ab-993f-45ae-8739-b4d4b164d665",
                        "CVE-2013-4793",
                        "OSSINDEX-839c2594-0439-4583-aff0-2ac010299de4"
                ),
                vulnerableDependencies.get("UmbracoCms:6.0.0").getVulnerabilities().keySet()
        );
    }

    @Test
    public void testCveVulnerabilityDetails(){
        final DAVulnerability vulnerability = vulnerableDependencies.get("UmbracoCms:6.0.0").getVulnerabilities().get("CVE-2013-4793");
        assertEquals("Improper Authentication", vulnerability.getTitle());
        assertEquals("CVE-2013-4793", vulnerability.getIdentifier());
        assertEquals(
                "The update function in umbraco.webservices/templates/templateService.cs in the TemplateService" +
                        " component in Umbraco CMS before 6.0.4 does not require authentication, which allows remote" +
                        " attackers to execute arbitrary ASP.NET code via a crafted SOAP request.",
                vulnerability.getDescription()
                );
        assertEquals(Optional.of("CVE-2013-4793"), vulnerability.getOptionalCve());
        assertEquals("6.0.0", vulnerability.getAfectedVersions());
        assertEquals("dcf81085-0de1-47a1-ae60-dfa6f18ca0b8", vulnerability.getOssIndexId());
        assertEquals("OSS Index", vulnerability.getProvidedBy());
    }

    @Test
    public void testOssIndexVulnerabilityDetails(){
        final DAVulnerability vulnerability = vulnerableDependencies.get("UmbracoCms:6.0.0").getVulnerabilities().get("OSSINDEX-b23f9aaa-db0a-4eb5-9c57-0eec46017953");
        assertEquals("Multiple vulnerabilities", vulnerability.getTitle());
        assertEquals("OSSINDEX-b23f9aaa-db0a-4eb5-9c57-0eec46017953", vulnerability.getIdentifier());
        assertEquals(
                "> During one of the regular security audits that independent security firms (in this case: MWR Labs) do of the core, a severe security vulnerability was found in the integration web services of Umbraco and we recommend everyone to take immediate action to prevent any exploit.> > ...\n" +
                        "for now we ask you to remove the following file from all your Umbraco installations:> > /bin/umbraco.webservices.dll> > -- [umbraco.com](https://umbraco.com/blog/security-vulnerability-found-immediate-action-recommended/)",
                vulnerability.getDescription()
        );
        assertEquals(Optional.empty(), vulnerability.getOptionalCve());
        assertEquals("b23f9aaa-db0a-4eb5-9c57-0eec46017953", vulnerability.getOssIndexId());
        assertEquals("OSS Index", vulnerability.getProvidedBy());
    }

    @Test
    public void testManyLinesVulnerabilityDetails(){
        final DAVulnerability vulnerability = vulnerableDependencies.get("LibGit2Sharp:0.20.0").getVulnerabilities().get("OSSINDEX-cfacab46-bdf8-40d4-8d50-06420a9c0013");
        assertEquals("Git vulnerability requires git client updates", vulnerability.getTitle());
        assertEquals("OSSINDEX-cfacab46-bdf8-40d4-8d50-06420a9c0013", vulnerability.getIdentifier());
        assertEquals(
                "A critical Git security vulnerability has been announced today, affecting all versions of the official Git client and all related software that interacts with Git repositories, including GitHub for Windows and GitHub for Mac.\n" +
                "Because this is a client-side only vulnerability, github.com and GitHub Enterprise are not directly affected.The vulnerability concerns Git and Git-compatible clients that access Git repositories in a case-insensitive or case-normalizing filesystem.\n" +
                "An attacker can craft a malicious Git tree that will cause Git to overwrite its own .git/config file when cloning or checking out a repository, leading to arbitrary command execution in the client machine.\n" +
                "Git clients running on OS X (HFS+) or any version of Microsoft Windows (NTFS, FAT) are exploitable through this vulnerability.\n" +
                "Linux clients are not affected if they run in a case-sensitive filesystem.",
                vulnerability.getDescription()
        );
        assertEquals(Optional.empty(), vulnerability.getOptionalCve());
        assertEquals("0.20.0", vulnerability.getAfectedVersions());
        assertEquals("cfacab46-bdf8-40d4-8d50-06420a9c0013", vulnerability.getOssIndexId());
        assertEquals("OSS Index", vulnerability.getProvidedBy());
    }

}
