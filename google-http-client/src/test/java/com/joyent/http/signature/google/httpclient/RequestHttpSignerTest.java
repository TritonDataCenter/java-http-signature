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
import com.joyent.http.signature.ThreadLocalSigner;
import org.testng.Assert;
import org.testng.annotations.*;
import org.testng.log4testng.Logger;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class RequestHttpSignerTest {
    private static final Logger LOG = Logger.getLogger(RequestHttpSignerTest.class);

    private static final String testKeyFingerprint = "04:92:7b:23:bc:08:4f:d7:3b:5a:38:9e:4a:17:2e:df";
    private KeyPair testKeyPair;
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
        this.testKeyPair = testKeyPair(signer.get());
    }

    @AfterClass
    public void cleanUp() {
        if (signer != null) {
            signer.clearAll();
        }
    }

    @Test
    @SuppressWarnings("deprecation")
    public void canSignUri() throws IOException {
        final String login = "user";
        final Signer signer = new Signer(this.useNativeCodeToSign);
        RequestHttpSigner requestSigner = new RequestHttpSigner(testKeyPair,
                login, testKeyFingerprint, useNativeCodeToSign);
        URI uri = URI.create("http://localhost/foo/bar");

        URI signedUri = requestSigner.signURI(uri, "GET", 0L);

        String expected = "http://localhost/foo/bar?algorithm=RSA-SHA256"
                + "&expires=0&keyId=%2Fuser%2Fkeys%2F04%3A92%3A7b%3A23%3"
                + "Abc%3A08%3A4f%3Ad7%3A3b%3A5a%3A38%3A9e%3A4a%3A17%3A2e"
                + "%3Adf&signature=sspA6KoRAtTjKN7wI3DNoMKVVWUfs0hvbr%2F"
                + "wa2Mu36Gz2D4ExjH0X84jRpF6XnadMZNdPc1JtTLkqLPAYpdZ9c34"
                + "U8zC0bu0cNJw3wri1hjr0XJDwjjF9lAu%2FXEJbh0r7vUcbF5Kwjy"
                + "hkjDr804Vp3br8IFFlxGl4%2BvsxerLU56PQPjWceHc56V5LcD7jE"
                + "q%2FNJdA0sVMerq0j2YRKyhhD%2BgndVSh5mG%2BipjJ6glDHnUt%"
                + "2BI3eME9do3xeua54%2FV7bIIO0%2BJz1kFPHzZL5kMKPa1XqVnra"
                + "zHUHje3j5QJcDrpmud2nVKKM4cw6FfOjEnrLVdD5w2eiTLiWJOcmT"
                + "USFBg%3D%3D";

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
        int iterations = 1000;

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

    /**
     * @return a static key pair used for testing utility methods
     */
    private KeyPair testKeyPair(final Signer signer) throws IOException {
        final ClassLoader loader = RequestHttpSigner.class.getClassLoader();

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
