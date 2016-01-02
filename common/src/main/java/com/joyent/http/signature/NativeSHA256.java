package com.joyent.http.signature;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSignatureSpi;

public class NativeSHA256 extends DigestSignatureSpi {
    public NativeSHA256() {
        super(NISTObjectIdentifiers.id_sha256, new SHA256Digest(), new PKCS1Encoding(new NativeRSABlindedEngine()));
    }


}
