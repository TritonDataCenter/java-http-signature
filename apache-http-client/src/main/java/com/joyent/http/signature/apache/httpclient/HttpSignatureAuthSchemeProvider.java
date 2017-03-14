/*
 * Copyright (c) 2016-2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature.apache.httpclient;

import com.joyent.http.signature.ThreadLocalSigner;
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
     * Deprecated flag that enables native code acceleration of cryptographic singing.
     */
    private final boolean useNativeCodeToSign;

    /**
     * Fully configured {@code Signer} to pass to instantiated {@code
     * AuthScheme}s.
     */
    private final ThreadLocalSigner signer;

    /**
     * Create a new instance of the provider.
     * @param keyPair Public/private keypair object used to sign HTTP requests.
     * @param useNativeCodeToSign true to enable native code acceleration of cryptographic singing
     *
     * @deprecated Prefer {@link #HttpSignatureAuthSchemeProvider(KeyPair, ThreadLocalSigner)}
     */
    @Deprecated
    public HttpSignatureAuthSchemeProvider(final KeyPair keyPair,
                                           final boolean useNativeCodeToSign) {
        this.keyPair = keyPair;
        this.useNativeCodeToSign = useNativeCodeToSign;
        this.signer = null;
    }

    /**
     * Create a new instance of the provider.
     * @param keyPair Public/private keypair object used to sign HTTP requests.
     * @param signer Configured Signer instance
     */
    public HttpSignatureAuthSchemeProvider(final KeyPair keyPair,
                                           final ThreadLocalSigner signer) {
        this.keyPair = keyPair;
        this.useNativeCodeToSign = false;
        this.signer = signer;
    }

    /**
     * Creates an instance of {@link AuthScheme}.
     *
     * @param context parameter not used
     * @return new instance of {@link AuthScheme}
     */
    @Override
    @SuppressWarnings("deprecation")
    public AuthScheme create(final HttpContext context) {
        if (signer != null) {
            return new HttpSignatureAuthScheme(keyPair, signer);
        } else {
            return new HttpSignatureAuthScheme(keyPair, useNativeCodeToSign);
        }
    }
}
