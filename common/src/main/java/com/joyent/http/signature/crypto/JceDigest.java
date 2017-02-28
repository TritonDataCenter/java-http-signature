/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature.crypto;

import com.joyent.http.signature.CryptoException;
import org.bouncycastle.crypto.Digest;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Wrapper interface that allows JCE {@link MessageDigest}
 * instances to function as BouncyCastle {@link Digest}
 * classes.
 */
public class JceDigest implements Digest {
    /**
     * Wrapped message digest.
     */
    private final MessageDigest messageDigest;

    /**
     * Creates a new digest by the JCE digest name.
     *
     * @param algorithm digest name
     */
    public JceDigest(final String algorithm) {
        try {
            this.messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Can't find digest algorithm ["
                    + algorithm + "]", e);
        }
    }

    /**
     * Creates a new instance that wraps the specified digest.
     *
     * @param messageDigest message digest to wrap
     */
    public JceDigest(final MessageDigest messageDigest) {
        this.messageDigest = messageDigest;
    }

    @Override
    public String getAlgorithmName() {
        return messageDigest.getAlgorithm();
    }

    @Override
    public int getDigestSize() {
        return messageDigest.getDigestLength();
    }

    @Override
    public void update(final byte in) {
        messageDigest.update(in);
    }

    @Override
    public void update(final byte[] in, final int inOff, final int len) {
        messageDigest.update(in, inOff, len);
    }

    @Override
    public int doFinal(final byte[] out, final int outOff) {
        try {
            return messageDigest.digest(out, outOff, out.length - outOff);
        } catch (DigestException e) {
            throw new CryptoException("Can't finalize digest", e);
        }
    }

    @Override
    public void reset() {
        messageDigest.reset();
    }
}
