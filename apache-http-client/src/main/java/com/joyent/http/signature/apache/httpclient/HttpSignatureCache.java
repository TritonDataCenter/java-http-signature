/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature.apache.httpclient;

import com.joyent.http.signature.HttpSignatureException;
import com.joyent.http.signature.Signer;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.Credentials;

import java.security.KeyPair;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Class that an interface to caching HTTP signatures for a given
 * {@link Credentials} instance.
 *
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 * @since 3.0.0
 */
class HttpSignatureCache {
    /**
     * Credentials to associate cache with.
     */
    private final Credentials credentials;

    /**
     * Reference to the date time of the last HTTP signature.
     */
    private final AtomicReference<String> lastDate = new AtomicReference<>("");

    /**
     * Reference to the last generated HTTP signature associated with this credential.
     */
    private final AtomicReference<String> lastSignature = new AtomicReference<>("");

    /**
     * Creates a new cache for the specified credential.
     *
     * @param credentials credentials to associate cache with
     */
    HttpSignatureCache(final Credentials credentials) {
        if (credentials == null) {
            throw new IllegalArgumentException("Credentials must be present");
        }

        if (credentials.getPassword() == null) {
            throw new IllegalArgumentException("Password (fingerprint) must be present");
        }

        if (credentials.getUserPrincipal() == null) {
            throw new IllegalArgumentException("User principal must be present");
        }

        if (credentials.getUserPrincipal().getName() == null) {
            throw new IllegalArgumentException("User principal name must be present");
        }

        this.credentials = credentials;
    }

    /**
     * Method that attempts to get a valid cached signature based on the
     * specified parameters. If a cached credential is not valid, then
     * a new signature will be generated and stored for later use in caching.
     *
     * @param stringDate date to use for HTTP signature
     * @param signer signer class to use for generating signature
     * @param keyPair cryptographic key pair to use for generating signature
     *
     * @return a valid HTTP signature string to be passed as a header value
     *
     * @throws AuthenticationException thrown if there is a problem authenticating the signature
     */
    String updateAndGetSignature(final String stringDate,
                                 final Signer signer,
                                 final KeyPair keyPair) throws AuthenticationException {

        if (lastDate.get().equals(stringDate)) {
            final String authz = lastSignature.get();
            if (!authz.isEmpty()) {
                return authz;
            }
            // if signature is empty, we fall below and store the new value
        }

        synchronized (this) {
            lastDate.set(stringDate);

            final String login = credentials.getUserPrincipal().getName();
            final String fingerprint = credentials.getPassword();

            // If date didn't match, then we calculate signature and store it

            try {
                String authz = signer.createAuthorizationHeader(
                        login, fingerprint, keyPair, stringDate);
                lastSignature.set(authz);

                return authz;
            } catch (HttpSignatureException e) {
                String details = String.format("Unable to authenticate [%s] with "
                                + "fingerprint [%s] using keypair [%s]",
                        login, fingerprint, keyPair);
                throw new AuthenticationException(details, e);
            }
        }
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        final HttpSignatureCache that = (HttpSignatureCache) o;
        return Objects.equals(lastDate.get(), that.lastDate.get())
               && Objects.equals(lastSignature.get(), that.lastSignature.get());
    }

    @Override
    public int hashCode() {
        return Objects.hash(lastDate.get(), lastSignature.get());
    }
}
