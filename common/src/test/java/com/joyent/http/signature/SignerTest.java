/**
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */
package com.joyent.http.signature;

import org.testng.Assert;
import org.testng.annotations.*;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class SignerTest {
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

        this.testKeyPair = SignerTestUtil.testKeyPair(new Signer(this.useNativeCodeToSign));
    }

    @Test
    public void signHeader() {
        final Signer signer = new Signer(useNativeCodeToSign);
        final String now = signer.defaultSignDateAsString();
        final String authzHeader = signer.createAuthorizationHeader(
                "testy", SignerTestUtil.testKeyFingerprint, testKeyPair, now);
        final boolean verified = signer.verifyAuthorizationHeader(
                testKeyPair, authzHeader, now);
        Assert.assertTrue(verified, "Unable to verify signed authorization header");
    }

    @Test
    public void signData() {
        final Signer signer = new Signer(useNativeCodeToSign);
        final byte[] data = "Hello World".getBytes();
        final byte[] signedData = signer.sign(
                "testy", SignerTestUtil.testKeyFingerprint, testKeyPair, data);
        final boolean verified = signer.verify(
                "testy", SignerTestUtil.testKeyFingerprint, testKeyPair, data, signedData);

        Assert.assertTrue(verified, "Signature couldn't be verified");
    }

}
