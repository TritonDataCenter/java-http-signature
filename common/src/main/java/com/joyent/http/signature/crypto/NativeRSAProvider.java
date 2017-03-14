/*
 * Copyright (c) 2016-2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature.crypto;

import java.security.Provider;

/**
 * JCE provider used for loading in native RSA SHA256 signing implementation.
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 */
public class NativeRSAProvider extends Provider {
    /**
     * Creates an instance of a JCE provider that supports native RSA via jnagmp.
     */
    public NativeRSAProvider() {
        super("native-rsa", 1.0, "SHA Digest with RSA Native implementation");
        put("Signature.SHA1withNativeRSA", NativeRSAWithSHA.SHA1.class.getName());
        put("Signature.SHA256withNativeRSA", NativeRSAWithSHA.SHA256.class.getName());
        put("Signature.SHA512withNativeRSA", NativeRSAWithSHA.SHA512.class.getName());
    }
}
