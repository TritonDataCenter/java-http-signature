/**
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */
package com.joyent.http.signature;

import org.testng.Assert;
import org.testng.annotations.*;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class SignerTest {
    private static final String testKeyFingerprint = "04:92:7b:23:bc:08:4f:d7:3b:5a:38:9e:4a:17:2e:df";
    private KeyPair testKeyPair;
    private boolean useNativeCodeToSign;

    @Parameters({"useNativeCodeToSign"})
    @BeforeClass
    public void beforeClass(@Optional Boolean useNativeCodeToSign) throws IOException, NoSuchAlgorithmException {
        if (useNativeCodeToSign == null) {
            this.useNativeCodeToSign = true;
        } else {
            this.useNativeCodeToSign = useNativeCodeToSign;
        }

        System.out.printf("Using native libgmp: %s\n", this.useNativeCodeToSign);

        this.testKeyPair = testKeyPair(new Signer(this.useNativeCodeToSign));
    }

    @Test
    public void signHeader() {
        final Signer signer = new Signer(useNativeCodeToSign);
        final String now = signer.defaultSignDateAsString();
        final String authzHeader = signer.createAuthorizationHeader(
                "testy", testKeyFingerprint, testKeyPair, now);
        final boolean verified = signer.verifyAuthorizationHeader(
                testKeyPair, authzHeader, now);
        Assert.assertTrue(verified, "Unable to verify signed authorization header");
    }

    @Test
    public void signData() {
        final Signer signer = new Signer(useNativeCodeToSign);
        final byte[] data = "Hello World".getBytes();
        final byte[] signedData = signer.sign(
                "testy", testKeyFingerprint, testKeyPair, data);
        final boolean verified = signer.verify(
                "testy", testKeyFingerprint, testKeyPair, data, signedData);

        Assert.assertTrue(verified, "Signature couldn't be verified");
    }

    /**
     * @return a static key pair used for testing utility methods
     */
    private KeyPair testKeyPair(final Signer signer) throws IOException {
        final ClassLoader loader = SignerTest.class.getClassLoader();

        // Try to get keypair from class path first
        try (InputStream is = loader.getResourceAsStream("id_rsa")) {
            KeyPair classPathPair = signer.getKeyPair(is, null);
            if (classPathPair != null) {
                return classPathPair;
            }
        }

        // We couldn't get the key pair from the class path, so let's try
        // a directory relative to the project root.
        Path keyPath = new File("./src/test/resources/id_rsa").toPath();
        return signer.getKeyPair(keyPath);
    }
}
