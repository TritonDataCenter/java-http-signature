/*
 * Copyright (c) 2016-2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature.crypto;

import com.joyent.http.signature.CryptoException;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSignatureSpi;
import org.bouncycastle.jcajce.provider.util.DigestFactory;

/**
 * Simple wrapper class for providing SHA256 RSA signing using native libraries.
 *
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 */
public class NativeSHA256 extends DigestSignatureSpi {
    /**
     * Creates a new instance configured with the default configuration.
     */
    public NativeSHA256() {
        super(NISTObjectIdentifiers.id_sha256,
              getDigest("SHA-256"),
              new PKCS1Encoding(new NativeRSABlindedEngine()));
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
}
