/**
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */
package com.joyent.http.signature.google.httpclient;

import com.joyent.http.signature.HttpSignerUtils;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class HttpSignerTest {
    private static final String testKeyFingerprint = "04:92:7b:23:bc:08:4f:d7:3b:5a:38:9e:4a:17:2e:df";
    private KeyPair testKeyPair;

    @BeforeClass
    public void beforeClass() throws IOException, NoSuchAlgorithmException {
        this.testKeyPair = testKeyPair();
    }

    @Test
    public void canSignUri() throws IOException {
        final String login = "user";
        HttpSigner signer = new HttpSigner(testKeyPair, login, testKeyFingerprint);
        URI uri = URI.create("http://localhost/foo/bar");
        URI signedUri = signer.signURI(uri, "GET", 0L);
    }

    /**
     * @return a static key pair used for testing utility methods
     */
    private static KeyPair testKeyPair() throws IOException {
        final ClassLoader loader = HttpSigner.class.getClassLoader();

        // Try to get keypair from class path first
        try (InputStream is = loader.getResourceAsStream("id_rsa")) {
            KeyPair classPathPair = HttpSignerUtils.getKeyPair(is, null);
            if (classPathPair != null) {
                return classPathPair;
            }
        }

        // We couldn't get the key pair from the class path, so let's try
        // a directory relative to the project root.
        Path keyPath = new File("./src/test/resources/id_rsa").toPath();
        return HttpSignerUtils.getKeyPair(keyPath);
    }
}
