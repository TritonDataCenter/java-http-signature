/**
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */
package com.joyent.http.signature.google.httpclient;

import com.google.api.client.http.HttpRequest;
import com.joyent.http.signature.CryptoException;
import com.joyent.http.signature.HttpSignerUtils;
import org.bouncycastle.util.encoders.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.UUID;

// I really really don't want to be using JUL for logging, but it is what the
// google library is using, so we are sticking with it. :(
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.joyent.http.signature.HttpSignerUtils.*;

/**
 * Class providing utility methods that allow you to sign a
 * {@link com.google.api.client.http.HttpRequest}.
 *
 * @see <a href="https://github.com/joyent/java-manta/blob/b2a180ff8a3ec3795ccc258904888f8305619756/src/main/java/com/joyent/manta/client/crypto/HttpSigner.java">Original Version</a>
 * @author Yunong Xiao
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 * @since 1.0.0
 */
public class HttpSigner {
    /**
     * The static logger instance.
     */
    private static final Logger LOG = Logger.getLogger(HttpSigner.class.getName());

    /**
     * Public/private RSA keypair object used to sign HTTP requests.
     */
    private final KeyPair keyPair;

    /**
     * Login name/account name used in authorization header.
     */
    private final String login;

    /**
     * The RSA key fingerprint.
     */
    private final String fingerprint;

    /**
     * Creates a new instance allowing for HTTP signing.
     * @param keyPair Public/private RSA keypair object used to sign HTTP requests.
     * @param login Login name/account name used in authorization header
     * @param fingerprint rsa key fingerprint
     */
    public HttpSigner(final KeyPair keyPair, final String login, final String fingerprint) {
        if (keyPair == null) {
            throw new IllegalArgumentException("KeyPair must be present");
        }

        if (login == null) {
            throw new IllegalArgumentException("Login must be present");
        }

        if (fingerprint == null) {
            throw new IllegalArgumentException("Fingerprint must be present");
        }

        this.keyPair = keyPair;
        this.login = login;
        this.fingerprint = fingerprint;
    }

    /**
     * Sign an {@link com.google.api.client.http.HttpRequest}.
     *
     * @param request The {@link com.google.api.client.http.HttpRequest} to sign.
     * @throws CryptoException If unable to sign the request.
     */
    public void signRequest(final HttpRequest request) {
        if (LOG.getLevel() != null && LOG.getLevel().equals(Level.FINER)) {
            LOG.finer(String.format("Signing request: %s", request.getHeaders()));
        }

        final UUID requestId = UUID.randomUUID();
        request.getHeaders().set(HttpSignerUtils.X_REQUEST_ID_HEADER,
                requestId.toString());

        final String date;
        if (request.getHeaders().getDate() != null) {
            date = request.getHeaders().getDate();
        } else {
            date = HttpSignerUtils.defaultSignDateAsString();
            request.getHeaders().setDate(date);
        }

        final String authzHeader = HttpSignerUtils.createAuthorizationHeader(
                login, fingerprint, keyPair, date);
        request.getHeaders().setAuthorization(authzHeader);
    }

    /**
     * Verifies the signature on a Google HTTP Client request.
     *
     * @param request request object to verify signature from
     * @return true if signature was verified correctly, otherwise false
     */
    public boolean verifyRequest(final HttpRequest request) {
        if (LOG.getLevel() != null && LOG.getLevel().equals(Level.FINER)) {
            LOG.finer(String.format("Verifying request: %s", request.getHeaders()));
        }
        String date = request.getHeaders().getDate();
        if (date == null) {
            throw new CryptoException("No date header in request");
        }

        date = String.format(AUTHZ_SIGNING_STRING, date);

        try {
            final Signature verify = Signature.getInstance(SIGNING_ALGORITHM);
            verify.initVerify(this.keyPair.getPublic());
            final String authzHeader = request.getHeaders().getAuthorization();
            final int startIndex = authzHeader.indexOf(AUTHZ_PATTERN);
            if (startIndex == -1) {
                throw new CryptoException("invalid authorization header " + authzHeader);
            }
            final String encodedSignedDate = authzHeader.substring(startIndex + AUTHZ_PATTERN.length(),
                    authzHeader.length() - 1);
            final byte[] signedDate = Base64.decode(encodedSignedDate.getBytes("UTF-8"));
            verify.update(date.getBytes("UTF-8"));
            return verify.verify(signedDate);
        } catch (final NoSuchAlgorithmException e) {
            throw new CryptoException("invalid algorithm", e);
        } catch (final InvalidKeyException e) {
            throw new CryptoException("invalid key", e);
        } catch (final SignatureException e) {
            throw new CryptoException("invalid signature", e);
        } catch (final UnsupportedEncodingException e) {
            throw new CryptoException("invalid encoding", e);
        }
    }
}
