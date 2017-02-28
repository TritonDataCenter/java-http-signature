/*
 * Copyright (c) 2016-2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature.apache.httpclient;

import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.protocol.HttpContext;

import java.security.KeyPair;

/**
 * Provides an new instance of {@link HttpSignatureAuthScheme}.
 *
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 * @since 2.0.3
 */
public class HttpSignatureAuthSchemeProvider implements AuthSchemeProvider {
    /**
     * Public/private keypair object used to sign HTTP requests.
     */
    private final KeyPair keyPair;

    /**
     * Flag that enables native code acceleration of cryptographic singing.
     */
    private final boolean useNativeCodeToSign;

    /**
     * Create a new instance of the provider.
     * @param keyPair Public/private keypair object used to sign HTTP requests.
     * @param useNativeCodeToSign true to enable native code acceleration of cryptographic singing
     */
    public HttpSignatureAuthSchemeProvider(final KeyPair keyPair,
                                           final boolean useNativeCodeToSign) {
        this.keyPair = keyPair;
        this.useNativeCodeToSign = useNativeCodeToSign;
    }

    /**
     * Creates an instance of {@link AuthScheme}.
     *
     * @param context parameter not used
     * @return new instance of {@link AuthScheme}
     */
    @Override
    public AuthScheme create(final HttpContext context) {
        return new HttpSignatureAuthScheme(keyPair, useNativeCodeToSign);
    }
}
