/**
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */
package com.joyent.http.signature.apache.httpclient;

import com.joyent.http.signature.HttpSignatureException;
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
import java.util.UUID;

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
    * Keypair used to sign requests.
    */
    private final KeyPair keyPair;

    /**
     * Thread local instance of {@link Signer}.
     */
    private final ThreadLocal<Signer> signer;

    /**
     * Creates a new instance allowing for HTTP signing.
     * @param keyPair Public/private keypair object used to sign HTTP requests.
     * @param useNativeCodeToSign true to enable native code acceleration of cryptographic singing
     */
    public HttpSignatureAuthScheme(final KeyPair keyPair, final boolean useNativeCodeToSign) {
        if (keyPair == null) {
            throw new IllegalArgumentException("KeyPair must be present");
        }

        this.keyPair = keyPair;
        this.signer = new ThreadLocalSigner(useNativeCodeToSign);
    }

    /**
     * Creates a new instance allowing for HTTP signing.
     * @param keyPair Public/private RSA keypair object used to sign HTTP requests.
     */
    public HttpSignatureAuthScheme(final KeyPair keyPair) {
        if (keyPair == null) {
            throw new IllegalArgumentException("KeyPair must be present");
        }

        this.keyPair = keyPair;
        this.signer = new ThreadLocalSigner();
    }

    @Override
    public void processChallenge(final Header header) throws MalformedChallengeException {

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
        final UUID requestId = UUID.randomUUID();
        request.setHeader(Signer.X_REQUEST_ID_HEADER, requestId.toString());

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
     * @param credentials Credentials containing a username and password
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

        if (credentials == null) {
            throw new IllegalArgumentException("Credentials must be present");
        }

        if (credentials.getPassword() == null) {
            throw new IllegalArgumentException("Password (RSA fingerprint) must be present");
        }

        if (credentials.getUserPrincipal() == null) {
            throw new IllegalArgumentException("User principal must be present");
        }

        if (credentials.getUserPrincipal().getName() == null) {
            throw new IllegalArgumentException("User principal name must be present");
        }

        final String login = credentials.getUserPrincipal().getName();
        final String fingerprint = credentials.getPassword();

        final Header date = request.getFirstHeader(HttpHeaders.DATE);
        final String stringDate;

        if (date != null) {
            stringDate = date.getValue();
        } else {
            stringDate = signer.get().defaultSignDateAsString();
            request.setHeader(HttpHeaders.DATE, stringDate);
        }

        final String authz;

        try {
            authz = signer.get().createAuthorizationHeader(
                    login, fingerprint, keyPair, stringDate);
        } catch (HttpSignatureException e) {
            String details = String.format("Unable to authenticate [%s] with "
                    + "fingerprint [%s] using keypair [%s]",
                    login, fingerprint, keyPair);
            throw new AuthenticationException(details, e);
        }

        final Header authzHeader = new BasicHeader(HttpHeaders.AUTHORIZATION, authz);

        return authzHeader;
    }
}
