/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

import com.joyent.http.signature.crypto.NssBridgeKeyConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
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
import java.security.Security;


/**
 * Utility class for instantiating {@code KeyPair}s from various
 * sources.
 */
public final class KeyPairLoader {


    @SuppressWarnings("checkstyle:javadocmethod")
    private KeyPairLoader() {
    }

    /**
     * The key format converter to use when reading key pairs.
     */
    private static final NssBridgeKeyConverter CONVERTER =
        new NssBridgeKeyConverter();
    {
        CONVERTER.setProvider("BC");
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
     * @param is private key content as a stream
     * @param password password associated with key
     * @return public/private keypair object
     * @throws IOException If unable to read the private key from the string
     */
    public static KeyPair getKeyPair(final InputStream is,
                              final char[] password) throws IOException {
        try (InputStreamReader isr = new InputStreamReader(is, StandardCharsets.US_ASCII);
             BufferedReader br = new BufferedReader(isr);
             PEMParser pemParser = new PEMParser(br)) {

            if (password == null) {
                Security.addProvider(new BouncyCastleProvider());
                final Object object = pemParser.readObject();
                return CONVERTER.getKeyPair((PEMKeyPair) object);
            } else {
                PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password);

                Object object = pemParser.readObject();

                final KeyPair kp;
                if (object instanceof PEMEncryptedKeyPair) {
                    kp = CONVERTER.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
                } else {
                    kp = CONVERTER.getKeyPair((PEMKeyPair) object);
                }

                return kp;
            }
        }
    }

}
