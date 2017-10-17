/**
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */
package com.joyent.http.signature;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

@SuppressWarnings("deprecation")
public class SignerLegacyConstructorTest {
    private KeyPair testKeyPair;
    private String testKeyFingerprint;
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

        this.testKeyPair = SignerTestUtil.testKeyPair("rsa_2048");
        this.testKeyFingerprint = SignerTestUtil.testKeyMd5Fingerprint("rsa_2048");
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
        final byte[] data = "Hello World".getBytes(StandardCharsets.US_ASCII);
        final byte[] signedData = signer.sign(
                "testy", testKeyFingerprint, testKeyPair, data);
        final boolean verified = signer.verify(
                "testy", testKeyFingerprint, testKeyPair, data, signedData);

        Assert.assertTrue(verified, "Signature couldn't be verified");
    }

}
