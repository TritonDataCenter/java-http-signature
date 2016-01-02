package com.joyent.http.signature.crypto;

import com.squareup.jnagmp.Gmp;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * <p>This is a copy of {@link RSABlindedEngine} with the RSA core engine
 * replace with a native implementation. We copied the library code here
 * because there is no better way to for us to inherit the properties.</p>
 *
 * <p>Note: there is a single change on line 118 - we use libgmp to do modpow.</p>
 *
 * <p>Relevant copyright belongs to:<br>
 * Copyright (c) 2000 - 2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * </p>
 *
 * @see org.bouncycastle.crypto.engines.RSABlindedEngine
 */
public class NativeRSABlindedEngine extends RSABlindedEngine {
    /**
     * The constant value of 1 as a {@link BigInteger}.
     */
    private static final BigInteger ONE = BigInteger.valueOf(1);

    /**
     * Reference to the native implementation of a {@link org.bouncycastle.crypto.engines.RSACoreEngine}.
     */
    private MantaNativeRSACoreEngine core = new MantaNativeRSACoreEngine();

    /**
     * RSA Key parameters.
     */
    private RSAKeyParameters key;

    /**
     * Source of randomness.
     */
    private SecureRandom random;

    /**
     * initialise the RSA engine.
     *
     * @param forEncryption true if we are encrypting, false otherwise.
     * @param param the necessary RSA key parameters.
     */
    public void init(final boolean forEncryption, final CipherParameters param) {
        core.init(forEncryption, param);

        if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom)param;

            key = (RSAKeyParameters)rParam.getParameters();
            random = rParam.getRandom();
        } else {
            key = (RSAKeyParameters)param;
            random = new SecureRandom();
        }
    }

    /**
     * Return the maximum size for an input block to this engine.
     * For RSA this is always one byte less than the key size on
     * encryption, and the same length as the key size on decryption.
     *
     * @return maximum size for an input block.
     */
    public int getInputBlockSize() {
        return core.getInputBlockSize();
    }

    /**
     * Return the maximum size for an output block to this engine.
     * For RSA this is always one byte less than the key size on
     * decryption, and the same length as the key size on encryption.
     *
     * @return maximum size for an output block.
     */
    public int getOutputBlockSize() {
        return core.getOutputBlockSize();
    }

    /**
     * Process a single block using the basic RSA algorithm.
     *
     * @param in the input array.
     * @param inOff the offset into the input buffer where the data starts.
     * @param inLen the length of the data to be processed.
     * @return the result of the RSA process.
     * @exception DataLengthException the input block is too large.
     */
    public byte[] processBlock(final byte[] in, final int inOff, final int inLen) {
        if (key == null) {
            throw new IllegalStateException("RSA engine not initialised");
        }

        BigInteger input = core.convertInput(in, inOff, inLen);

        BigInteger result;
        if (key instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters k = (RSAPrivateCrtKeyParameters)key;

            BigInteger e = k.getPublicExponent();
            // can't do blinding without a public exponent
            if (e != null) {
                BigInteger m = k.getModulus();
                BigInteger r = BigIntegers.createRandomInRange(ONE, m.subtract(ONE), random);

                // This is a modification to use the GMP native library method
                BigInteger blindedModPow = Gmp.modPowSecure(r, e, m);

                BigInteger blindedInput = blindedModPow.multiply(input).mod(m);
                BigInteger blindedResult = core.processBlock(blindedInput);

                BigInteger rInv = r.modInverse(m);
                result = blindedResult.multiply(rInv).mod(m);
                // defence against Arjen Lenstra’s CRT attack
                if (!input.equals(result.modPow(e, m))) {
                    throw new IllegalStateException("RSA engine faulty decryption/signing detected");
                }
            } else {
                result = core.processBlock(input);
            }
        } else {
            result = core.processBlock(input);
        }

        return core.convertOutput(result);
    }
}
