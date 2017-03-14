/*
 * Copyright (c) 2016-2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature.crypto;

import com.joyent.http.signature.CryptoException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSignatureSpi;
import org.bouncycastle.jcajce.provider.util.DigestFactory;

/**
 * Simple wrapper class for providing RSA signing using native libraries.
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 */
public abstract class NativeRSAWithSHA extends DigestSignatureSpi {

    /**
     * @see org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSignatureSpi
     *
     * @param objId reflected to parent
     * @param digest reflected to parent
     * @param cipher reflected to parent
     */
    protected NativeRSAWithSHA(final ASN1ObjectIdentifier objId,
                               final Digest digest,
                               final AsymmetricBlockCipher cipher) {
        super(objId, digest, cipher);
    }

    /**
     * Finds checksum by name.
     *
     * @param digest digest name
     * @return digest instance
     */
    private static Digest getDigest(final String digest) {
        try {
            return new JceDigest(digest);
        } catch (CryptoException e) {
            String noHyphen = digest.replaceFirst("-", "");
            return DigestFactory.getDigest(noHyphen);
        }
    }

    /** {@inheritDoc}.
     */
    public static class SHA1 extends NativeRSAWithSHA {
        /**
         * Creates a new instance configured with the default configuration.
         */
        public SHA1() {
            super(OIWObjectIdentifiers.idSHA1,
                  getDigest("SHA-1"),
                  new PKCS1Encoding(new NativeRSABlindedEngine()));
        }
    }

    /** {@inheritDoc}.
     */
    public static class SHA256 extends NativeRSAWithSHA {
        /**
         * Creates a new instance configured with the default configuration.
         */
        public SHA256() {
            super(NISTObjectIdentifiers.id_sha256,
                  getDigest("SHA-256"),
                  new PKCS1Encoding(new NativeRSABlindedEngine()));
        }
    }

    /** {@inheritDoc}.
     */
    public static class SHA512 extends NativeRSAWithSHA {
        /**
         * Creates a new instance configured with the default configuration.
         */
        public SHA512() {
            super(NISTObjectIdentifiers.id_sha512,
                  getDigest("SHA-512"),
                  new PKCS1Encoding(new NativeRSABlindedEngine()));
        }
    }
}
