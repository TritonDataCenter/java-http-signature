/**
 * Copyright (c) 2016, Joyent, Inc. All rights reserved.
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
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.client.AuthenticationStrategy;
import org.apache.http.config.Lookup;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HttpContext;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
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
     * Immutable list of challenges that always return HTTP Signatures.
     */
    private final Map<String, Header> allChallenges;

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
        authOption = new AuthOption(authScheme, credentials);

        Map<String, Header> temp;
        temp = new HashMap<>(1);
        temp.put("Signatures", new BasicHeader("Authorization", "Signatures"));
        this.allChallenges = Collections.unmodifiableMap(temp);
    }

    /**
     * Determines if the given HTTP response response represents
     * an authentication challenge that was sent back as a result
     * of authentication failure.
     *
     * @param authhost authentication host.
     * @param response HTTP response.
     * @param context  HTTP context.
     * @return {@code true} if user authentication is required,
     * {@code false} otherwise.
     */
    @Override
    public boolean isAuthenticationRequested(final HttpHost authhost,
                                             final HttpResponse response,
                                             final HttpContext context) {
        final StatusLine line = response.getStatusLine();
        return line.getStatusCode() == HttpStatus.SC_UNAUTHORIZED;
    }

    @Override
    public Map<String, Header> getChallenges(final HttpHost authhost,
                                             final HttpResponse response,
                                             final HttpContext context)
            throws MalformedChallengeException {
        return allChallenges;
    }

    @Override
    public Queue<AuthOption> select(final Map<String, Header> challenges,
                                    final HttpHost authhost,
                                    final HttpResponse response,
                                    final HttpContext context)
            throws MalformedChallengeException {
        Queue<AuthOption> queue = new LinkedList<>();
        queue.add(authOption);

        return queue;
    }

    @Override
    public void authSucceeded(final HttpHost authhost,
                              final AuthScheme authScheme,
                              final HttpContext context) {
        LOG.debug("HTTP Signature authentication succeeded");
    }

    @Override
    public void authFailed(final HttpHost authhost, final AuthScheme authScheme,
                           final HttpContext context) {
        LOG.debug("HTTP Signature authentication failed");
    }
}
