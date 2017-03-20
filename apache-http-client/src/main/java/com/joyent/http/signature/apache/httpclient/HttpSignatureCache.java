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

/**
 * <p>Class that an interface to caching HTTP signatures for a given
 * {@link Credentials} instance.</p>
 *
 * <p>HTTP signature dates have a resolution of one second. If a two signatures
 * are requested for the exact same signature date time (within 1 second), then
 * we do not need to recalculate the signature (a computationally expensive
 * operation). In order to accomplish this, this class contains two fields
 * that cache the last signature date time and the last signature. Using the
 * cache, when two requests come through with the same date time, then we only
 * need to calculate the signature for a single request.</p>
 *
 * <p>This class maintains a cache per {@link Credentials} object because
 * the signature will differ due to different credentials using different
 * signing keys.</p>
 *
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 * @since 4.0.0
 */
class HttpSignatureCache {
    /**
     * Credentials to associate cache with.
     */
    private final Credentials credentials;

    /**
     * The date time of the last HTTP signature.
     */
    private String lastDate = "";

    /**
     * The last generated HTTP signature associated with this credential.
     */
    private String lastSignature = "";

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
    synchronized String updateAndGetSignature(final String stringDate,
                                              final Signer signer,
                                              final KeyPair keyPair)
            throws AuthenticationException {

        // Signing date time is equal, so we returned cached signature
        // stringDate parameter should *never* be null or blank
        if (lastDate.equals(stringDate)) {
            return lastSignature;
        }

        lastDate = stringDate;

        final String login = credentials.getUserPrincipal().getName();
        final String fingerprint = credentials.getPassword();

        // If date didn't match, then we calculate signature and store it
        try {
            final String authz = signer.createAuthorizationHeader(
                    login, fingerprint, keyPair, stringDate);
            lastSignature = authz;

            return authz;
        } catch (HttpSignatureException e) {
            String details = String.format("Unable to authenticate [%s] with "
                            + "fingerprint [%s] using keypair [%s]",
                    login, fingerprint, keyPair);
            throw new AuthenticationException(details, e);
        }
    }
}
