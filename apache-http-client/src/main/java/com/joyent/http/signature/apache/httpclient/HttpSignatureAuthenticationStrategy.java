/*
 * Copyright (c) 2016-2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature.apache.httpclient;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.auth.AuthOption;
import org.apache.http.auth.AuthProtocolState;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthState;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.client.AuthCache;
import org.apache.http.client.AuthenticationStrategy;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Lookup;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.protocol.HttpContext;

import java.util.Collections;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;

/**
 * {@link AuthenticationStrategy} implementation that allows the Apache HTTP
 * Client to authenticate via the HTTP Signature scheme.
 *
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 * @since 2.0.3
 */
public class HttpSignatureAuthenticationStrategy implements AuthenticationStrategy {
    /**
     * The static logger instance.
     */
    private static final Log LOG = LogFactory.getLog(HttpSignatureAuthScheme.class);

    /**
     * Immutable list of challenges with a single dummy value because for our purposes
     * all that matters is that this map is not empty.
     */
    private final Map<String, Header> challenges = Collections.singletonMap(null, null);

    /**
     * AuthOption that always returns {@link HttpSignatureAuthScheme}.
     */
    private final AuthOption authOption;

    /**
     * Create a new instance using a provider found via a {@link Lookup}.
     *
     * @param authSchemeProviderLookup Lookup that will return an {@link AuthScheme}
     *                                 when asked for "Signatures"
     * @param credentials credentials containing the HTTP Signature username
     *                    and fingerprint
     */
    public HttpSignatureAuthenticationStrategy(
            final Lookup<AuthSchemeProvider> authSchemeProviderLookup,
            final Credentials credentials) {
        this(authSchemeProviderLookup.lookup("Signatures").create(null), credentials);
    }

    /**
     * Creates a new instance using the passed authentication scheme.
     *
     * @param authScheme authentication scheme to use to authenticate
     *                   requests (expecting {@link HttpSignatureAuthScheme})
     * @param credentials credentials containing the HTTP Signature username
     *                    and fingerprint
     */
    public HttpSignatureAuthenticationStrategy(final AuthScheme authScheme,
                                               final Credentials credentials) {
        this.authOption = new AuthOption(authScheme, credentials);
    }

    /**
     * Determines if the given HTTP response response represents
     * an authentication challenge that was sent back as a result
     * of authentication failure.
     *
     * @param authHost authentication host.
     * @param response HTTP response.
     * @param context  HTTP context.
     * @return {@code true} if user authentication is required,
     *                      {@code false} otherwise.
     */
    @Override
    public boolean isAuthenticationRequested(final HttpHost authHost,
                                             final HttpResponse response,
                                             final HttpContext context) {
        final StatusLine line = response.getStatusLine();
        final int code = line.getStatusCode();
        final HttpClientContext clientContext = HttpClientContext.adapt(context);

        final AuthState authState = clientContext.getTargetAuthState();
        final AuthProtocolState authProtocolState = authState.getState();

        if (code == HttpStatus.SC_UNAUTHORIZED) {
            if (authProtocolState.equals(AuthProtocolState.CHALLENGED)) {
                clientContext.getTargetAuthState().setState(AuthProtocolState.FAILURE);
                authFailed(authHost, authState.getAuthScheme(), context);
            }

            return true;
        }

        if (clientContext.getTargetAuthState() == null) {
            return true;
        }

        return false;
    }

    @Override
    public Map<String, Header> getChallenges(final HttpHost authhost,
                                             final HttpResponse response,
                                             final HttpContext context)
            throws MalformedChallengeException {

        /* Unfortunately, we have to abuse the challenge functionality in
         * because it won't enabled authentication unless at least a single
         * challenge is available. The HTTP response for a HTTP Signatures
         * API will never contain a challenge header, so effectively any
         * headers that are added will never match. */

        return this.challenges;
    }

    @Override
    public Queue<AuthOption> select(final Map<String, Header> challengeHeaders,
                                    final HttpHost authhost,
                                    final HttpResponse response,
                                    final HttpContext context)
            throws MalformedChallengeException {
        final HttpClientContext httpClientContext = HttpClientContext.adapt(context);
        final AuthState state = httpClientContext.getTargetAuthState();
        final Queue<AuthOption> queue = new LinkedList<>();

        if (state == null || !state.getState().equals(AuthProtocolState.CHALLENGED)) {
            queue.add(authOption);
        } else {
            System.out.println("does this happen?");
        }

        return queue;
    }

    @Override
    public void authSucceeded(final HttpHost authhost,
                              final AuthScheme authScheme,
                              final HttpContext context) {
        Objects.requireNonNull(authhost, "Authentication host must be present");
        Objects.requireNonNull(authScheme, "Authentication scheme must be present");
        Objects.requireNonNull(context, "HTTP context must be present");

        LOG.debug("HTTP Signature authentication succeeded");

        final HttpClientContext clientContext = HttpClientContext.adapt(context);

        AuthCache authCache = clientContext.getAuthCache();
        if (authCache == null) {
            authCache = new BasicAuthCache();
            clientContext.setAuthCache(authCache);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Caching '" + authScheme.getSchemeName()
                    + "' auth scheme for " + authhost);
        }
        authCache.put(authhost, authScheme);
    }

    @Override
    public void authFailed(final HttpHost authhost,
                           final AuthScheme authScheme,
                           final HttpContext context) {
        Objects.requireNonNull(authhost, "Authentication host must be present");
        Objects.requireNonNull(context, "HTTP context must be present");

        LOG.debug("HTTP Signature authentication failed");

        final HttpClientContext clientContext = HttpClientContext.adapt(context);

        final AuthCache authCache = clientContext.getAuthCache();
        if (authCache != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Clearing cached auth scheme for " + authhost);
            }
            authCache.remove(authhost);
        }
    }
}
