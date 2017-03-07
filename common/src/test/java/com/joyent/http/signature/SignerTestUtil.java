/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

import java.security.KeyPair;
import java.io.IOException;
import java.io.InputStream;


public class SignerTestUtil {
    public static final String testKeyFingerprint = "04:92:7b:23:bc:08:4f:d7:3b:5a:38:9e:4a:17:2e:df";

    /**
     * @return a static key pair used for testing utility methods
     */
    public static KeyPair testKeyPair(final Signer signer) throws IOException {
        final ClassLoader loader = SignerTestUtil.class.getClassLoader();

        try (InputStream is = loader.getResourceAsStream("keys/rsa/id_rsa_2048")) {
            KeyPair classPathPair = signer.getKeyPair(is, null);
            return classPathPair;
        }
    }

}
