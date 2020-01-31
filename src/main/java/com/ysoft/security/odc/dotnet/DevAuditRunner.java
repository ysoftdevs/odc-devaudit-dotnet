package com.ysoft.security.odc.dotnet;

import org.apache.commons.collections.map.ReferenceMap;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.SystemUtils;
import org.owasp.dependencycheck.utils.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Collections.emptyMap;
import static java.util.function.Function.identity;
import static org.apache.commons.collections.map.AbstractReferenceMap.HARD;
import static org.apache.commons.collections.map.AbstractReferenceMap.SOFT;
import static org.apache.commons.lang3.StringEscapeUtils.escapeXml10;

public class DevAuditRunner {

    private static final Logger LOGGER = LoggerFactory.getLogger(DevAuditRunner.class);

    private final Path devAuditPath;

    @SuppressWarnings("unchecked")
    private final Map<String, DAVulnerableDependency> cache = new ReferenceMap(HARD, SOFT);

    public DevAuditRunner(Path devAuditPath) {
        this.devAuditPath = devAuditPath;
    }

    public Map<String, DAVulnerableDependency> run(Path packagesConfigPath) throws IOException {
        final ProcessBuilder processBuilder = new ProcessBuilder(
                ArrayUtils.addAll(devAuditExe(), "nuget", "-n", "--file", packagesConfigPath.resolve("packages.config").toString())
        );
        processBuilder.redirectErrorStream(true);
        final Process process = processBuilder.start();
        try{
            process.getOutputStream().close();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                final Map<String, DAVulnerableDependency> res = DevAuditResultParser.parse(reader);
                process.waitFor();
                final int exitValue = process.exitValue();
                if(exitValue != 0){
                    throw new IOException("Error when running DevAudit: Unexpected exit code: "+exitValue);
                }
                return res;
            }
        } catch (InterruptedException e){
            throw new IOException(e);
        } finally {
            process.destroyForcibly();
        }
    }

    private String[] devAuditExe() throws IOException {
        final String devAuditNativePath = devAuditPath.resolve("devaudit").toString();
        final String devAuditExePath = devAuditPath.resolve("devaudit.exe").toString();
        return new File(devAuditNativePath).exists()
            ? new String[]{devAuditNativePath}
            : (SystemUtils.IS_OS_WINDOWS || hasCliBinfmt())
                ? new String[]{devAuditExePath}
                : new String[]{findDotNetRuntime(), devAuditExePath};
    }

    private String findDotNetRuntime() throws IOException {
        final Process process = Runtime.getRuntime().exec("which cli mono");
        try {
            new Thread(() -> {
                try (InputStream errorStream = process.getErrorStream()) {
                    final byte[] buffer = new byte[1024];
                    while (errorStream.read(buffer) != -1) {
                        // ignore
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }).start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                return reader.readLine();
            }
        } finally {
            process.destroy();
        }
    }

    private boolean hasCliBinfmt() {
        return new File("/proc/sys/fs/binfmt_misc/cli").exists();
    }

    public synchronized Map<String, DAVulnerableDependency> run(List<String> identifiers) throws IOException {
        if(identifiers.isEmpty()){
            return emptyMap();
        }
        final Map<String, DAVulnerableDependency> cached = loadFromCache(identifiers);
        final HashSet<String> missing = new HashSet<>(identifiers);
        missing.removeAll(cached.keySet());
        LOGGER.info("Cache hits: {}", cached.keySet());
        LOGGER.info("Cache misses: {}", missing);
        if(missing.isEmpty()){ // fast path
            return cached;
        }
        final Path tempProjectDir = Files.createTempDirectory(null);
        try {
            final StringBuilder xmlBuilder = new StringBuilder(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                    "<packages>\n"
            );
            for (final String identifier: missing) {
                final String[] identifierParts = identifier.split(":");
                if(identifierParts.length != 2){
                    throw new UnexpectedFormatException("Unexpected count of colons in identifier: "+identifier);
                }
                final String name = identifierParts[0];
                final String version = identifierParts[1];
                xmlBuilder.append("  <package id=\"").append(escapeXml10(name)).append("\" version=\"").append(escapeXml10(version)).append("\" />\n");
            }
            xmlBuilder.append("</packages>\n");
            final String xml = xmlBuilder.toString();
            LOGGER.debug("packages.config: {}", xml);
            Files.write(tempProjectDir.resolve("packages.config"), xml.getBytes(StandardCharsets.UTF_8));
            final Map<String, DAVulnerableDependency> missingResults = new HashMap<>(missing.stream().collect(Collectors.toMap(identity(), DAVulnerableDependency::withNoVulnerability)));
            missingResults.putAll(run(tempProjectDir));
            cache.putAll(missingResults);

            final Map<String, DAVulnerableDependency> result = new HashMap<>(cached);
            result.putAll(missingResults);
            return result;
        } finally {
            Files.walkFileTree(tempProjectDir, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path path, BasicFileAttributes basicFileAttributes) throws IOException {
                    Files.delete(path);
                    return FileVisitResult.CONTINUE;
                }
                @Override
                public FileVisitResult postVisitDirectory(Path path, IOException e) throws IOException {
                    Files.delete(path);
                    return FileVisitResult.CONTINUE;
                }
            });
        }
    }

    private synchronized Map<String, DAVulnerableDependency> loadFromCache(List<String> identifiers) {
        return identifiers.stream()
                .map(identifier -> new Pair<>(identifier, cache.get(identifier)))
                .filter(p -> p.getRight() != null)
                .collect(Collectors.toMap(Pair::getLeft, Pair::getRight));
    }

}
