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
import org.apache.http.auth.Credentials;
import org.apache.http.client.AuthenticationStrategy;
import org.apache.http.impl.client.HttpClientBuilder;

import java.security.KeyPair;

/**
 * Configuration helper class for configuring a {@link HttpClientBuilder} to use
 * HTTP Signatures authentication.
 *
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 * @since 2.0.5
 */
public class HttpSignatureConfigurator {
    /**
     * Public/private keypair object used to sign HTTP requests.
     */
    private final KeyPair keyPair;

    /**
     * Credentials containing a username.
     */
    private final Credentials credentials;

    /**
     * Authentication scheme to use to authenticate requests.
     */
    private final HttpSignatureAuthScheme authScheme;

    /**
     * Authentication strategy instance that is assigned to all requests configured in the
     * {@link HttpClientBuilder}.
     */
    private final AuthenticationStrategy authenticationStrategy;

    /**
     *  Creates a new instance.
     *
     * @param keyPair public/private keypair object used to sign HTTP requests
     * @param credentials credentials containing a username
     * @param useNativeCodeToSign true to enable native code acceleration of cryptographic singing
     *
     * @deprecated Prefer {@link #HttpSignatureConfigurator(KeyPair,
     * Credentials, ThreadLocalSigner)} if configuration of Signer
     * algorithm, hashes, or providers is required.
     */
    @Deprecated
    public HttpSignatureConfigurator(final KeyPair keyPair,
                                     final Credentials credentials,
                                     final boolean useNativeCodeToSign) {
        this.keyPair = keyPair;
        this.credentials = credentials;
        this.authScheme = new HttpSignatureAuthScheme(keyPair, useNativeCodeToSign);
        this.authenticationStrategy = new HttpSignatureAuthenticationStrategy(authScheme,
                credentials);
    }

    /**
     *  Creates a new instance.
     *
     * @param keyPair public/private keypair object used to sign HTTP requests
     * @param credentials credentials containing a username
     * @param signer For use with http signature
     */
    public HttpSignatureConfigurator(final KeyPair keyPair,
                                     final Credentials credentials,
                                     final ThreadLocalSigner signer) {
        this.keyPair = keyPair;
        this.credentials = credentials;
        this.authScheme = new HttpSignatureAuthScheme(keyPair, signer);
        this.authenticationStrategy = new HttpSignatureAuthenticationStrategy(authScheme,
                credentials);
    }


    /**
     * Configures a {@link HttpClientBuilder} to use HTTP Signature authentication.
     *
     * @param httpClientBuilder build to configure
     */
    public void configure(final HttpClientBuilder httpClientBuilder) {
        httpClientBuilder.setTargetAuthenticationStrategy(authenticationStrategy);
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public Credentials getCredentials() {
        return credentials;
    }

    public AuthScheme getAuthScheme() {
        return authScheme;
    }

    public AuthenticationStrategy getAuthenticationStrategy() {
        return authenticationStrategy;
    }
}
