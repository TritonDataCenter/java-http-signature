/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;


public class SignerTestUtil {
    public static final Map<String,TestKeyResource> keys = new HashMap<String,TestKeyResource>() {{
            put("rsa_2048", new TestKeyResource("04:92:7b:23:bc:08:4f:d7:3b:5a:38:9e:4a:17:2e:df",
                                                "keys/rsa/id_rsa_2048"));
            put("dsa_1024", new TestKeyResource("5e:9a:ce:fe:5a:24:f9:7a:06:d8:94:b8:e4:ae:c4:99",
                                                "keys/dsa/id_dsa_1024"));
            put("ecdsa_256", new TestKeyResource("d3:11:55:74:8f:25:78:f0:29:2a:e7:b7:30:ed:3d:a0",
                                                  "keys/ecdsa/ecdsa_256"));


        }};

    public static String testKeyFingerprint(String keyId) {
        return keys.get(keyId).fingerprint;
    }

    public static KeyPair testKeyPair(String keyId) throws IOException {
        final ClassLoader loader = SignerTestUtil.class.getClassLoader();

        try (InputStream is = loader.getResourceAsStream(keys.get(keyId).resourcePath)) {
            KeyPair classPathPair = KeyPairLoader.getKeyPair(is, null);
            return classPathPair;
        }
    }

    public static class TestKeyResource {
        public final String fingerprint;
        public final String resourcePath;

        public TestKeyResource(String fingerprint, String resourcePath) {
            this.fingerprint = fingerprint;
            this.resourcePath = resourcePath;
        }
    }

}
