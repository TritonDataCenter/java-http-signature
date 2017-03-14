/*
 * Copyright (c) 2016-2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature.apache.httpclient;

import com.joyent.http.signature.ThreadLocalSigner;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.config.Lookup;

import java.security.KeyPair;

/**
 * {@link org.apache.http.config.Lookup} implementation that provides a
 * default mapping to an HTTP signatures
 * {@link org.apache.http.auth.AuthSchemeProvider}.
 *
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 * @since 2.0.3
 */
public class HttpSignatureAuthSchemeProviderLookup implements Lookup<AuthSchemeProvider> {
    /**
     * Backing instance of provider used for all lookups.
     */
    private final HttpSignatureAuthSchemeProvider authSchemeProvider;

    /**
     * Create a new instance of the lookup with the passed provider.
     * @param authSchemeProvider provider to use to back lookup calls
     */
    public HttpSignatureAuthSchemeProviderLookup(
            final HttpSignatureAuthSchemeProvider authSchemeProvider) {
        this.authSchemeProvider = authSchemeProvider;
    }

    /**
     * Create a new instance of the lookup with a new provider setup with the
     * passed key.
     * @param keyPair Public/private keypair object used to sign HTTP requests.
     * @param useNativeCodeToSign true to enable native code acceleration of cryptographic singing
     *
     * @deprecated Prefer {@link #HttpSignatureAuthSchemeProviderLookup(KeyPair, ThreadLocalSigner)}
     */
    @Deprecated
    public HttpSignatureAuthSchemeProviderLookup(
            final KeyPair keyPair, final boolean useNativeCodeToSign) {
        this.authSchemeProvider = new HttpSignatureAuthSchemeProvider(
                keyPair, useNativeCodeToSign);
    }

    /**
     * Create a new instance of the lookup with a new provider setup with the
     * passed key.
     *
     * @param keyPair Public/private keypair object used to sign HTTP requests.
     * @param signer Configured Signer instance
     */
    public HttpSignatureAuthSchemeProviderLookup(
            final KeyPair keyPair, final ThreadLocalSigner signer) {
        this.authSchemeProvider = new HttpSignatureAuthSchemeProvider(
                keyPair, signer);
    }

    @Override
    public AuthSchemeProvider lookup(final String name) {
        if (name.equalsIgnoreCase(HttpSignatureAuthScheme.SCHEME_NAME)) {
            return authSchemeProvider;
        } else {
            return null;
        }
    }
}
