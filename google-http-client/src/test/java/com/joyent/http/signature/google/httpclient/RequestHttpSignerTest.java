/**
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */
package com.joyent.http.signature.google.httpclient;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.testing.http.MockHttpTransport;
import com.joyent.http.signature.Signer;
import com.joyent.http.signature.SignerTestUtil;
import com.joyent.http.signature.ThreadLocalSigner;
import org.testng.Assert;
import org.testng.annotations.*;
import org.testng.log4testng.Logger;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

@SuppressWarnings("deprecation")
public class RequestHttpSignerTest {
    private static final Logger LOG = Logger.getLogger(RequestHttpSignerTest.class);

    private KeyPair testKeyPair;
    private String testKeyFingerprint;
    private boolean useNativeCodeToSign;
    private ThreadLocalSigner signer;

    @Parameters({"useNativeCodeToSign"})
    @BeforeClass
    public void beforeClass(@Optional Boolean useNativeCodeToSign) throws IOException, NoSuchAlgorithmException {
        if (useNativeCodeToSign == null) {
            this.useNativeCodeToSign = true;
        } else {
            this.useNativeCodeToSign = useNativeCodeToSign;
        }

        this.signer = new ThreadLocalSigner(this.useNativeCodeToSign);
        // Removes any existing instances - so that we can reset state
        this.signer.remove();
        this.testKeyPair = SignerTestUtil.testKeyPair("rsa_2048");
        this.testKeyFingerprint = SignerTestUtil.testKeyFingerprint("rsa_2048");
    }

    @AfterClass
    public void cleanUp() {
        if (signer != null) {
            signer.clearAll();
        }
    }

    @Test
    public void canSignUri() throws IOException {
        final String login = "user";
        final Signer signer = new Signer(this.useNativeCodeToSign);
        RequestHttpSigner requestSigner = new RequestHttpSigner(testKeyPair,
                login, testKeyFingerprint, useNativeCodeToSign);
        URI uri = URI.create("http://localhost/foo/bar");

        URI signedUri = requestSigner.signURI(uri, "GET", 0L);

        String expected = "http://localhost/foo/bar?algorithm=RSA-SHA256&expires=0&keyId=%2Fuser%2Fkeys%2Fa5%3A75%3Ae2%3A5e%3A54%3A0e%3A99%3A9d%3Af0%3Aa9%3A16%3A8c%3A1d%3A88%3Adc%3Ab4&signature=l7ScY1r7R4E%2BmCgDWBJ5ShoOVqp93h2csUuISZXz63V2xBKLJiQEXUW626ur2X3rRRVDa0KS2eWf%2BwWy9SgqMUjwoCAbXivuvsKEkJVuBz9RrDb%2BC9oZgWRqNfGoBY824FoMgIJFZBF0yIFlIa1Qij%2FNOeOP%2BCzMXFdi2J5RjIQ7PZqKUwe%2BAM3vS2TkBoyRk%2FYw0tCTDglx4oOAS7ulNQUHzyKma0k2z5C6jIfv1ab19tl8lYnmgvk6FFV6iLT3dlqMzFtXdD1DeHKkXR2JUIxm9%2BdD3FULGnMl8sunlN%2FUb4paytxc%2Ff81f2o%2BI0369y3Y8N3E9Ly1Q0ATQq6QJQ%3D%3D";

        Assert.assertEquals(signedUri.toString(), expected);
    }

    @Test
    public void canSignRequest() throws IOException {
        final String login = "user";
        RequestHttpSigner requestSigner = new RequestHttpSigner(testKeyPair, login,
                testKeyFingerprint, useNativeCodeToSign);

        Signer signer = requestSigner.getSignerThreadLocal().get();

        System.out.printf("Signer implementation: %s", signer);

        HttpTransport transport = new MockHttpTransport();
        HttpRequestFactory factory = transport.createRequestFactory();

        GenericUrl get = new GenericUrl("http://localhost/foo/bar");
        HttpRequest request = factory.buildGetRequest(get);

        long running = 0L;
        int iterations = 5;

        for (int i = 0; i < iterations; i++) {
            long start = System.currentTimeMillis();
            requestSigner.signRequest(request);
            long end = System.currentTimeMillis();

            long total = end - start;
            running += total;
            Assert.assertTrue(requestSigner.verifyRequest(request));
            System.out.println(String.format("Total signing time for request: %dms", total));
        }

        long average = Math.round(running / iterations);
        System.out.println(String.format("Average signing time: %dms", average));

        String authorization = request.getHeaders().getAuthorization();

        LOG.info("Authorization: " + authorization);
    }
}
