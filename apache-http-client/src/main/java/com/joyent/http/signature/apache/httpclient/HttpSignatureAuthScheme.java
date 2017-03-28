/*
 * Copyright (c) 2015-2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature.apache.httpclient;

import com.joyent.http.signature.Signer;
import com.joyent.http.signature.ThreadLocalSigner;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.ContextAwareAuthScheme;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HttpContext;

import java.security.KeyPair;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;

/**
 * Apache HTTP Client plugin that allows for HTTP Signature based authentication.
 *
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 * @since 1.0.0
 */
@SuppressWarnings("deprecation")
public class HttpSignatureAuthScheme implements ContextAwareAuthScheme {
    /**
     * Name of authentication scheme.
     */
    public static final String SCHEME_NAME = "Signatures";

    /**
     * The static logger instance.
     */
    private static final Log LOG = LogFactory.getLog(HttpSignatureAuthScheme.class);

    /**
     * Anonymous function class that creates new cache instances based
     * on the passed credential.
     */
    private static final Function<Credentials, HttpSignatureCache>
            NEW_CACHE_FUNCTION = HttpSignatureCache::new;

    /**
    * Keypair used to sign requests.
    */
    private final KeyPair keyPair;

    /**
     * Thread local instance of {@link Signer}.
     */
    private final ThreadLocalSigner signer;

    /**
     * Map of credentials to cache object used for looking up cached signatures.
     */
    private ConcurrentMap<Credentials, HttpSignatureCache> signatureCacheMap =
        new ConcurrentHashMap<>();


    /**
     * Creates a new instance allowing for HTTP signing with default
     * settings.  An internal {@link
     * com.joyent.http.signature.ThreadLocalSigner} instance will be
     * created.
     *
     * @param keyPair Public/private  keypair object used to sign HTTP requests.
     */
    public HttpSignatureAuthScheme(final KeyPair keyPair) {
        this(keyPair, true);
    }


    /**
     * Creates a new instance allowing for HTTP signing with default
     * settings.  An internal {@link
     * com.joyent.http.signature.ThreadLocalSigner} instance will be
     * created.
     *
     * @param keyPair Public/private keypair object used to sign HTTP requests.
     * @param useNativeCodeToSign true to enable native code acceleration of cryptographic singing
     *
     * @deprecated Prefer #HttpSignatureAuthScheme(final KeyPair
     * keyPair, final Signer) if configuration of Signer algorithm,
     * hashes, or providers is required.
     */
    @Deprecated
    public HttpSignatureAuthScheme(final KeyPair keyPair, final boolean useNativeCodeToSign) {
        this(keyPair, new ThreadLocalSigner());
    }


    /**
     * Creates a new instance allowing for HTTP signing.
     *
     * @param keyPair Public/private keypair object used to sign HTTP requests.
     * @param signer {@link
     * com.joyent.http.signature.ThreadLocalSigner} to use for all
     * signed requests.
     */
    public HttpSignatureAuthScheme(final KeyPair keyPair, final ThreadLocalSigner signer) {
        if (keyPair == null) {
            throw new IllegalArgumentException("KeyPair must be present");
        }

        this.keyPair = keyPair;
        this.signer = signer;
    }


    @Override
    public void processChallenge(final Header header) throws MalformedChallengeException {
        /* We error here because HTTP signature based authentication doesn't
         * work on a challenge response model. Even if we get passed a header there
         * is no response header available for us to process. */

        throw new IllegalStateException("No challenge should ever occur");
    }

    @Override
    public String getSchemeName() {
        return SCHEME_NAME;
    }

    @Override
    public String getParameter(final String name) {
        return null;
    }

    @Override
    public String getRealm() {
        return null;
    }

    @Override
    public boolean isConnectionBased() {
        return false;
    }

    @Override
    public boolean isComplete() {
        return true;
    }

    @Override
    public Header authenticate(final Credentials credentials,
                               final HttpRequest request,
                               final HttpContext context)
            throws AuthenticationException {
        return signRequestHeader(credentials, request);
    }

    @Override
    public Header authenticate(final Credentials credentials,
                               final HttpRequest request)
            throws AuthenticationException {
        return authenticate(credentials, request, null);
    }

    @Override
    public String toString() {
        return getSchemeName().toUpperCase(Locale.ROOT);
    }

    /**
     * Signs an {@link HttpRequest} and returns a header with the signed
     * authorization value.
     *
     * @param credentials Credentials containing a username
     * @param request The {@link HttpRequest} to sign.
     * @return header with signed authorization value
     * @throws AuthenticationException If unable to sign the request.
     */
    protected Header signRequestHeader(final Credentials credentials,
                                       final HttpRequest request)
            throws AuthenticationException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Signing request: %s", request));
        }

        final Header date = request.getFirstHeader(HttpHeaders.DATE);
        final String stringDate;

        if (date != null) {
            stringDate = date.getValue();
        } else {
            stringDate = signer.get().defaultSignDateAsString();
            request.setHeader(HttpHeaders.DATE, stringDate);
        }

        // Assure that a cache object is always present for each credential
        signatureCacheMap.computeIfAbsent(credentials, NEW_CACHE_FUNCTION);

        final String authz = signatureCacheMap.get(credentials)
                .updateAndGetSignature(stringDate, signer.get(), keyPair);
        return new BasicHeader(HttpHeaders.AUTHORIZATION, authz);
    }

    public ThreadLocalSigner getSigner() {
        return signer;
    }
}
