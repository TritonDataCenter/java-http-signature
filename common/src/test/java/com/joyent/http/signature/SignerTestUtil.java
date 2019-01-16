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
    @SuppressWarnings({"serial", "DoubleBraceInitialization"})
    public static final Map<String,TestKeyResource> keys = new HashMap<String,TestKeyResource>() {{
            put("rsa_1024", new TestKeyResource("9f:0b:50:ae:e3:da:f6:eb:b5:71:9a:69:ee:79:9e:c2",
                                                "LP3pWCEhg6rdmE05GhUKbZ7uOZqsJd0sK0AR3sVoMq4",
                                                "keys/rsa/id_rsa_1024"));
            put("rsa_2048", new TestKeyResource("a5:75:e2:5e:54:0e:99:9d:f0:a9:16:8c:1d:88:dc:b4",
                                                "HRNiA5tYl1tjJKAh/Z7YAjq4ilXKs/jsbawuvtSNGQI",
                                                "keys/rsa/id_rsa_2048"));
            put("rsa_3072", new TestKeyResource("a8:42:93:a4:98:99:e9:ff:8c:c5:f1:d5:6d:26:2e:23",
                                                "3utlYbfy35NuXLFSLdd+ZTIm/l102INyMM/Dsx+7Rzw",
                                                "keys/rsa/id_rsa_3072"));
            put("rsa_4096", new TestKeyResource("82:c2:6b:ad:41:b5:dd:65:88:ec:46:d2:a6:4a:f0:9b",
                                                "oM3St/9DeJslewe4G9BxWcBt8P0L8OVVTEqGT0OBaZA",
                                                "keys/rsa/id_rsa_4096"));
            put("dsa_1024", new TestKeyResource("5e:9a:ce:fe:5a:24:f9:7a:06:d8:94:b8:e4:ae:c4:99",
                                                "VKNhg7WSNC7PYPHkUoe2CEXcYRR67clcjsQEJQ3jWWE",
                                                "keys/dsa/id_dsa_1024"));
            put("ecdsa_256", new TestKeyResource("d3:11:55:74:8f:25:78:f0:29:2a:e7:b7:30:ed:3d:a0",
                                                 "02guwBUSayfOYL5AgTvQ9KnSnK4d31OWPRf5berK9aI",
                                                 "keys/ecdsa/ecdsa_256"));
            put("ecdsa_384", new TestKeyResource("c7:b6:fe:e5:64:70:8d:03:ec:f2:a8:56:b2:fb:10:16",
                                                 "9Wvr6LiU0Tb2auluS+F2MiIFrIUvuAjcoz2xSNwL6s0",
                                                 "keys/ecdsa/ecdsa_384"));
            put("ecdsa_521", new TestKeyResource("6d:7c:31:25:03:15:a9:94:f7:0c:eb:ed:72:91:91:ac",
                                                 "O7LoGu1rijNCSkCsho/43x+ffBAsSQf+sKz36/h0HXI",
                                                 "keys/ecdsa/ecdsa_521"));

        }};

    public static String testKeyMd5Fingerprint(String keyId) {
        return keys.get(keyId).md5Fingerprint;
    }

    public static String testKeySha256Fingerprint(String keyId) {
        return keys.get(keyId).sha256Fingerprint;
    }

    public static KeyPair testKeyPair(String keyId) throws IOException {
        final ClassLoader loader = SignerTestUtil.class.getClassLoader();

        try (InputStream is = loader.getResourceAsStream(keys.get(keyId).resourcePath)) {
            KeyPair classPathPair = KeyPairLoader.getKeyPair(is, null, null);
            return classPathPair;
        }
    }

    public static class TestKeyResource {
        public final String md5Fingerprint;
        public final String sha256Fingerprint;
        public final String resourcePath;

        public TestKeyResource(String md5Fingerprint, String sha256Fingerprint, String resourcePath) {
            this.md5Fingerprint = md5Fingerprint;
            this.sha256Fingerprint = sha256Fingerprint;
            this.resourcePath = resourcePath;
        }
    }
}
