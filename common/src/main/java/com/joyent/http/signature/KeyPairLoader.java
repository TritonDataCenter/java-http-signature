/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;


/**
 * Utility class for instantiating {@code KeyPair}s from various
 * sources.
 */
public final class KeyPairLoader {

    /**
     * Provider name for libnss.
     */
    public static final String PROVIDER_PKCS11_NSS = "SunPKCS11-NSS";

    /**
     * Provider name for Bouncy Castle.
     */
    public static final String PROVIDER_BOUNCY_CASTLE = "BC";

    /**
     * The key format converter to use when reading key pairs and libnss is enabled (or specifically requested).
     */
    private static final JcaPEMKeyConverter CONVERTER_PKCS11_NSS;

    /**
     * The key format converter to use when libnss is disabled (or BC is specifically requested).
     */
    private static final JcaPEMKeyConverter CONVERTER_BOUNCY_CASTLE;

    /**
     * Set of security providers users can request.
     */
    @SuppressWarnings({"checkstyle:JavaDocVariable", "checkstyle:JavadocMethod"})
    public enum DesiredSecurityProvider {
        BC(PROVIDER_BOUNCY_CASTLE),
        NSS(PROVIDER_PKCS11_NSS);

        private final String providerCode;

         DesiredSecurityProvider(final String providerCode) {
            this.providerCode = providerCode;
        }

        @Override
        public String toString() {
             return providerCode;
        }
    }

    static {
        final Provider providerPkcs11NSS = Security.getProvider(PROVIDER_PKCS11_NSS);

        if (providerPkcs11NSS != null) {
            CONVERTER_PKCS11_NSS = new JcaPEMKeyConverter().setProvider(PROVIDER_PKCS11_NSS);
        } else {
            CONVERTER_PKCS11_NSS = null;
        }

        final Provider providerBouncyCastle = Security.getProvider(PROVIDER_BOUNCY_CASTLE);

        if (providerBouncyCastle == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        CONVERTER_BOUNCY_CASTLE = new JcaPEMKeyConverter().setProvider(PROVIDER_BOUNCY_CASTLE);
    }

    @SuppressWarnings("checkstyle:javadocmethod")
    private KeyPairLoader() {
    }

    /**
     * Read KeyPair from the specified file.
     *
     * @param keyFile The file containing the key
     *
     * @return public-private keypair object
     * @throws IOException If unable to read the private key from the file
     */
    public static KeyPair getKeyPair(final File keyFile) throws IOException {
        return getKeyPair(keyFile.toPath(), null);
    }

    /**
     * Read KeyPair from the specified file.
     *
     * @param keyFile The file containing the key
     * @param password password associated with key
     *
     * @return public-private keypair object
     * @throws IOException If unable to read the private key from the file
     */
    public static KeyPair getKeyPair(final File keyFile, final char[] password) throws IOException {
        return getKeyPair(keyFile.toPath(), password);
    }

    /**
     * Read KeyPair located at the specified path.
     *
     * @param keyPath The path to the key

     * @return public-private keypair object
     * @throws IOException If unable to read the private key from the file
     */
    public static KeyPair getKeyPair(final Path keyPath) throws IOException {
        return getKeyPair(keyPath, null);
    }

    /**
     * Read KeyPair located at the specified path.
     *
     * @param keyPath The path to the key
     * @param password password associated with key

     * @return public-private keypair object
     * @throws IOException If unable to read the private key from the file
     */
    public static KeyPair getKeyPair(final Path keyPath, final char[] password) throws IOException {
        if (keyPath == null) {
            throw new FileNotFoundException("No key file path specified");
        }

        if (!Files.exists(keyPath)) {
            throw new FileNotFoundException(
                    String.format("No key file available at path: %s", keyPath));
        }

        if (!Files.isReadable(keyPath)) {
            throw new IOException(
                    String.format("Can't read key file from path: %s", keyPath));
        }

        try (InputStream is = Files.newInputStream(keyPath)) {
            return getKeyPair(is, password);
        }
    }

    /**
     * Read KeyPair from a string, optionally using password.
     *
     * @param privateKeyContent private key content as a string
     * @param password password associated with key
     * @return public-private keypair object
     * @throws IOException If unable to read the private key from the string
     */
    public static KeyPair getKeyPair(final String privateKeyContent, final char[] password) throws IOException {
        byte[] pKeyBytes = privateKeyContent.getBytes(StandardCharsets.US_ASCII);

        return getKeyPair(pKeyBytes, password);
    }

    /**
     * Read KeyPair from a string, optionally using password.
     *
     * @param pKeyBytes private key content as a byte array
     * @param password password associated with key
     * @return public-private keypair object
     * @throws IOException If unable to read the private key from the string
     */
    public static KeyPair getKeyPair(final byte[] pKeyBytes, final char[] password) throws IOException {
        if (pKeyBytes == null) {
            throw new IllegalArgumentException("pKeyBytes must be present");
        }

        try (InputStream is = new ByteArrayInputStream(pKeyBytes)) {
            return getKeyPair(is, password);
        }
    }

    /**
     * Read KeyPair from an input stream, optionally using password.
     *
     * @param is       private key content as a stream
     * @param password password associated with key
     * @return public/private keypair object
     * @throws IOException If unable to read the private key from the string
     */
    public static KeyPair getKeyPair(final InputStream is,
                                     final char[] password) throws IOException {
        return getKeyPair(is, password, null);
    }

    /**
     * Read KeyPair from an input stream, optionally using password and desired Security Provider. Most implementations
     * should continue calling the one and two-argument methods
     *
     * @param is       private key content as a stream
     * @param password password associated with key
     * @param provider security provider to use when loading the key
     * @return public/private keypair object
     * @throws IOException If unable to read the private key from the string
     */
    public static KeyPair getKeyPair(final InputStream is,
                                     final char[] password,
                                     final DesiredSecurityProvider provider) throws IOException {
        final Object pemObject;
        try (InputStreamReader isr = new InputStreamReader(is, StandardCharsets.US_ASCII);
             BufferedReader br = new BufferedReader(isr);
             PEMParser pemParser = new PEMParser(br)) {

            pemObject = pemParser.readObject();
        }

        final PEMKeyPair pemKeyPair;

        if (pemObject instanceof PEMEncryptedKeyPair) {
            if (password == null) {
                throw new KeyLoadException("Loaded key is encrypted but no password was supplied.");
            }

            final PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder().build(password);
            final PEMEncryptedKeyPair encryptedPemObject = ((PEMEncryptedKeyPair) pemObject);
            pemKeyPair = encryptedPemObject.decryptKeyPair(decryptorProvider);
        } else if (pemObject instanceof PEMKeyPair) {
            if (password != null) {
                throw new KeyLoadException("Loaded key is not encrypted but a password was supplied.");
            }

            pemKeyPair = (PEMKeyPair) pemObject;
        } else {
            throw new KeyLoadException("Unexpected PEM object loaded: " + pemObject.getClass().getCanonicalName());
        }

        // throw if the user has specifically requested NSS and it is unavailable
        if (provider != null && provider.equals(DesiredSecurityProvider.NSS) && CONVERTER_PKCS11_NSS == null) {
            throw new KeyLoadException(PROVIDER_PKCS11_NSS + " provider requested but unavailable. "
                    + "Is java.security configured correctly?");
        }

        // Attempt to load with NSS if it is available and requested (or no provider was specified)
        final boolean attemptPKCS11NSS = provider == null || provider.equals(DesiredSecurityProvider.NSS);

        if (CONVERTER_PKCS11_NSS != null && attemptPKCS11NSS) {
            return CONVERTER_PKCS11_NSS.getKeyPair(pemKeyPair);
        }

        return CONVERTER_BOUNCY_CASTLE.getKeyPair(pemKeyPair);
    }

}
