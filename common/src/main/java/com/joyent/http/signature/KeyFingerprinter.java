/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;


import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Objects;

/**
 * Utiility class for calculating and verifying SSH key fingerprints as defined by OpenSSH.
 */
public final class KeyFingerprinter {

    /**
     * OpenSSH does not pad.
     */
    private static Base64.Encoder b64Encoder = Base64.getEncoder().withoutPadding();

    /**
     * Hexadecimal characters to translate to when converting from a byte[]
     * array to a hex string.
     */
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    @SuppressWarnings("checkstyle:javadocmethod")
    private KeyFingerprinter() {
    }

    /**
     * Prior to version 6.7 used an a hex encoded MD5 of the
     * serialized public key as a fingerprint.  This representation is
     * still the one used by Triton and Manta as the key id.
     *
     * @param keyPair The KeyPair to calculate the fingerprint of
     * @return The fingerprint (ex: {@code 9f:0b:50:ae:e3:da:f6:eb:b5:71:9a:69:ee:79:9e:c2})
     */
    public static String md5Fingerprint(final KeyPair keyPair) {
        Objects.requireNonNull(keyPair);
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            // Every implementation of the Java platform is required
            // to support the following standard MessageDigest
            // algorithms: MD5, SHA-1, SHA-256
            throw new AssertionError(e);
        }
        byte[] encoded = SshEncoder.encode(keyPair.getPublic());
        md.update(encoded);
        byte[] digest = md.digest();
        return colonify(digest);
    }

    /**
     * Starting with version 6.8 OpenSSH used the base64 encoded
     * SHA256 of the serialized public key as a fingerprint.
     *
     * @param keyPair The KeyPair to calculate the fingerprint of
     * @return The fingerprint (ex: {@code: LP3pWCEhg6rdmE05GhUKbZ7uOZqsJd0sK0AR3sVoMq4})
     */
    public static String sha256Fingerprint(final KeyPair keyPair) {
        Objects.requireNonNull(keyPair);
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // Every implementation of the Java platform is required
            // to support the following standard MessageDigest
            // algorithms: MD5, SHA-1, SHA-256
            throw new AssertionError(e);
        }
        byte[] encoded = SshEncoder.encode(keyPair.getPublic());
        md.update(encoded);
        byte[] digest = md.digest();
        return b64Encoder.encodeToString(digest);
    }

    /**
     * Verifies that the given fingerprint matches the key.  The
     * fingerprint can be in any of the formats used by OpenSSH
     * including the pre-6.7 format ({@code
     * 9f:0b:50:ae:e3:da:f6:eb:b5:71:9a:69:ee:79:9e:c2}), or 6.8
     * format prefixed with the algorithm name ({@code
     * MD5:9f:0b:50:ae:e3:da:f6:eb:b5:71:9a:69:ee:79:9e:c2} or {@code
     * SHA256:LP3pWCEhg6rdmE05GhUKbZ7uOZqsJd0sK0AR3sVoMq4}).
     *
     * @param keyPair The KeyPair to calculate the fingerprint of
     * @param fingerprint The expected fingerprint
     * @return true of the fingerprint matches
     */

    public static boolean verifyFingerprint(final KeyPair keyPair, final String fingerprint) {
        Objects.requireNonNull(keyPair);
        Objects.requireNonNull(fingerprint);
        final String md5Prefix = "MD5:";
        final String sha256Prefix = "SHA256:";

        if (fingerprint.startsWith(md5Prefix)) {
            String expected = fingerprint.substring(md5Prefix.length());
            return expected.equals(md5Fingerprint(keyPair));
        } else if (fingerprint.startsWith(sha256Prefix)) {
            String expected = fingerprint.substring(sha256Prefix.length());
            return expected.equals(sha256Fingerprint(keyPair));
        } else {
            return fingerprint.equals(md5Fingerprint(keyPair));
        }
    }

    /**
     * Given a byte array, space it out with colons and
     * lowercase each character to match the OpenSSH format.
     * Example output would be {@code
     * 9f:0b:50:ae:e3:da:f6:eb:b5:71:9a:69:ee:79:9e:c2}
     *
     * @param bytes byte array to convert to hex string
     * @return hex string with colons
     */
    @SuppressWarnings("MagicNumber")
    static String colonify(final byte[] bytes) {
        Objects.requireNonNull(bytes, "byte array is null");

        if (bytes.length == 0) {
            return "";
        }

        final char[] chars = new char[bytes.length * 3 - 1];

        int charPos = 0;
        for (int i = 0; i < bytes.length; i++) {
            final int val = bytes[i] & 0xFF;
            chars[charPos++] = HEX_CHARS[val >>> 4];
            chars[charPos++] = HEX_CHARS[val & 0x0F];

            if (charPos + 1 < chars.length) {
                chars[charPos++] = ':';
            }
        }

        return new String(chars);
    }

    /*
     * OpenSSH generally uses its own serialized representation of
     * public keys.  This is different from the ASN.1 or X.509 format
     * that may be returned by Java's getEncoded() method.  Each key
     * type necessarily has its own format as well.  In general the
     * representation includes a name followed by a series of
     * arbitrarily large integers serialized as length+bytes.  This is
     * based on the work in the node-sshpk project.  The specific
     * ordering of the encoded pieces (ie the exponent and modulus for
     * RSA) is also based on node-sshpk.
     */
    @SuppressWarnings({"checkstyle:magicnumber", "checkstyle:javadocmethod", "checkstyle:javadoctype"})
    private static class SshEncoder {

        public static byte[] encode(final PublicKey key) {
            if (key instanceof RSAPublicKey) {
                return encode((RSAPublicKey)key);
            } else if (key instanceof DSAPublicKey) {
                return encode((DSAPublicKey)key);
            } else if (key instanceof ECPublicKey) {
                return encode((ECPublicKey)key);
            } else {
                throw new CryptoException("unknown public key type: " + key.getClass().getName());
            }
        }

        // sshpk parts: ['e', 'n']
        public static byte[] encode(final RSAPublicKey key) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] name = "ssh-rsa".getBytes(StandardCharsets.US_ASCII);
            writeArray(name, buf);
            writeArray(key.getPublicExponent().toByteArray(), buf);
            writeArray(key.getModulus().toByteArray(), buf);
            return buf.toByteArray();
        }

        // sshpk: ['p', 'q', 'g', 'y']
        public static byte[] encode(final DSAPublicKey key) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] name = "ssh-dss".getBytes(StandardCharsets.US_ASCII);
            writeArray(name, buf);
            writeArray(key.getParams().getP().toByteArray(), buf);
            writeArray(key.getParams().getQ().toByteArray(), buf);
            writeArray(key.getParams().getG().toByteArray(), buf);
            writeArray(key.getY().toByteArray(), buf);
            return buf.toByteArray();
        }

        /*
         * sshpk parts: ['curve', 'Q']
         *
         * Unfortunately the ECDSA serialization is a bit quirky.
         * Both the "name" and "curve name" strings are are used, and
         * they include the "key size" (ex: nistp256).  A larger
         * complication is that "Q" (the elliptic curve point) is not
         * a simple big int but a compound representation of the
         * coordinates.  The is described in details in RFC 5656 and
         * the "SEC 1: Elliptic Curve Cryptography"
         * <http://www.secg.org/sec1-v2.pdf> paper on which the RFD
         * depends.  Fortunately, the point representation is the same
         * as the ASN.1 representation used by Java, so we can let the
         * standard library do all of the bit twiddling and grab the
         * appropriate bytes at the end.
         *
         * These details are summarized by
         * https://security.stackexchange.com/a/129913
         */
        public static byte[] encode(final ECPublicKey key) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();

            int bitLength = key.getW().getAffineX().bitLength();
            String curveName = null;
            int qLen;
            if (bitLength <= 256) {
                curveName = "nistp256";
                qLen = 65;
            } else if (bitLength <= 384) {
                curveName = "nistp384";
                qLen = 97;
            } else if (bitLength <= 521) {
                curveName = "nistp521";
                qLen = 133;
            } else {
                throw new CryptoException("ECDSA bit length unsupported: " + bitLength);
            }

            byte[] name = ("ecdsa-sha2-" + curveName).getBytes(StandardCharsets.US_ASCII);
            byte[] curve = curveName.getBytes(StandardCharsets.US_ASCII);
            writeArray(name, buf);
            writeArray(curve, buf);

            byte[] javaEncoding = key.getEncoded();
            byte[] q = new byte[qLen];

            System.arraycopy(javaEncoding, javaEncoding.length - qLen, q, 0, qLen);
            writeArray(q, buf);

            return buf.toByteArray();
        }

        /*
         * The OpenSSH serialization format can in principle express a
         * variety of types.  Fortunately only byte arrays
         * (representing either strings or big integers) are required
         * to represent public keys.  They are serialized as the
         * length (requiring the unsigned int conversion) followed by
         * the bytes.
         */
        public static void writeArray(final byte[] arr, final ByteArrayOutputStream baos) {
            for (int shift = 24; shift >= 0; shift -= 8) {
                baos.write((arr.length >>> shift) & 0xFF);
            }
            baos.write(arr, 0, arr.length);
        }
    }
}
