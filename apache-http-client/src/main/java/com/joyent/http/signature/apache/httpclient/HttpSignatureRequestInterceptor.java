/*
 * Copyright (c) 2016-2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature.apache.httpclient;

import org.apache.http.Header;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.auth.Credentials;
import org.apache.http.protocol.HttpContext;

import java.io.IOException;

/**
 * Alternative to HTTP Client {@link org.apache.http.auth.AuthScheme} approach
 * that uses a {@link org.apache.http.HttpRequestInterceptor} to perform
 * HTTP signature authentication.
 *
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 * @since 3.0.0
 */
public class HttpSignatureRequestInterceptor implements HttpRequestInterceptor {
    /**
     * Flag indicating that HTTP signature authentication is enabled.
     */
    private final boolean authEnabled;

    /**
     * Authentication scheme instance to use to create authentication header.
     */
    private final HttpSignatureAuthScheme authScheme;

    /**
     * Credentials of the user authenticating using HTTP signatures.
     */
    private final Credentials credentials;

    /**
     * Creates a new instance.
     *
     * @param authScheme authentication scheme used to generate signature
     * @param credentials credentials of user authenticating
     * @param authEnabled flag indicating if authentication is enabled
     */
    public HttpSignatureRequestInterceptor(final HttpSignatureAuthScheme authScheme,
                                           final Credentials credentials,
                                           final boolean authEnabled) {
        this.authScheme = authScheme;
        this.credentials = credentials;
        this.authEnabled = authEnabled;
    }

    @Override
    public void process(final HttpRequest request, final HttpContext context)
            throws HttpException, IOException {
        if (!authEnabled) {
            return;
        }

        final Header authorization = authScheme.authenticate(
                this.credentials, request, context);
        request.setHeader(authorization);
    }
}
