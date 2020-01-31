package com.ysoft.security.odc.dotnet;

import org.junit.Test;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.*;

public class DllAnalyzerTest {

    private void assertIsDotNet(String name) throws IOException {
        assertTrue(name + " is expected to be a .NET library.", isResourceDotNet(name));
    }

    private void assertIsNotDotNet(String name) throws IOException {
        assertFalse(name + " is not expected to be a .NET library.", isResourceDotNet(name));
    }

    private boolean isResourceDotNet(String name) throws IOException {
        final Path tempFile = Files.createTempFile(null, null);
        try (InputStream in = getClass().getResourceAsStream("/dll-samples/"+name)) {
            if(in == null){
                throw new FileNotFoundException(name);
            }
            try (FileOutputStream outputStream = new FileOutputStream(tempFile.toFile())) {
                final byte[] buffer = new byte[4096];
                int size;
                while((size = in.read(buffer)) != -1){
                    outputStream.write(buffer, 0, size);
                }
            }
            return DllAnalyzer.isDotNet(tempFile.toFile());
        } finally {
            Files.delete(tempFile);
        }
    }

    @Test
    public void isDotNet() throws Exception {
        // Just take a bunch of real libraries and test it…
        assertIsDotNet("AutoMapper.dll");
        assertIsDotNet("Google.Protobuf.dll");
        assertIsDotNet("BouncyCastle.Crypto.dll");
        assertIsDotNet("Microsoft.Owin.Host.SystemWeb.dll");
        assertIsDotNet("wix.dll");
        assertIsDotNet("Renci.SshNet.dll");
        assertIsDotNet("Renci.SshNet.Silverlight.dll");
        assertIsDotNet("EntityFramework.dll");
        assertIsDotNet("Newtonsoft.Json.dll");
        assertIsNotDotNet("grpc_csharp_ext.x64.dll");
        assertIsNotDotNet("HanSoneConnect.dll");
        assertIsNotDotNet("lilli.dll");
        assertIsNotDotNet("msvcr90.dll");
        assertIsNotDotNet("python27.dll");
        assertIsNotDotNet("sqlceqp40.dll");
        assertIsNotDotNet("SyncBraille.dll");
        assertIsNotDotNet("VSDebugUI.dll");
        assertIsNotDotNet("winterop.dll");
        // And also some non-DLL file
        assertIsNotDotNet("../out.new2.log");
    }

}