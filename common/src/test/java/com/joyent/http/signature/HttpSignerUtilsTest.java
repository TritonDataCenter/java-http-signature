/**
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */
package com.joyent.http.signature;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.*;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class HttpSignerUtilsTest {
    private static final String testKeyFingerprint = "04:92:7b:23:bc:08:4f:d7:3b:5a:38:9e:4a:17:2e:df";
    private KeyPair testKeyPair;

    @BeforeClass
    public void beforeClass() throws IOException, NoSuchAlgorithmException {
        this.testKeyPair = testKeyPair();
    }

    @Test
    public final void signData() {
        final String now = HttpSignerUtils.defaultSignDateAsString();
        final String authzHeader = HttpSignerUtils.createAuthorizationHeader(
                "testy", testKeyFingerprint, testKeyPair, now);
        final boolean verified = HttpSignerUtils.verifyAuthorizationHeader(
                testKeyPair, authzHeader, now);
        Assert.assertTrue(verified, "Unable to verify signed authorization header");
    }

    /**
     * @return a static key pair used for testing utility methods
     */
    private static KeyPair testKeyPair() throws IOException {
        final ClassLoader loader = HttpSignerUtilsTest.class.getClassLoader();

        // Try to get keypair from class path first
        try (InputStream is = loader.getResourceAsStream("id_rsa")) {
            KeyPair classPathPair = HttpSignerUtils.getKeyPair(is, null);
            if (classPathPair != null) {
                return classPathPair;
            }
        }

        // We couldn't get the key pair from the class path, so let's try
        // a directory relative to the project root.
        Path keyPath = new File("./src/test/resources/is_rsa").toPath();
        return HttpSignerUtils.getKeyPair(keyPath);
    }
}
