package com.joyent.http.signature.crypto;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSignatureSpi;

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
              new SHA256Digest(),
              new PKCS1Encoding(new NativeRSABlindedEngine()));
    }
}
