package com.joyent.http.signature.crypto;

import java.security.Provider;

/**
 * JCE provider used for loading in native RSA SHA256 signing implementation.
 *
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 */
public class NativeRSAProvider extends Provider {
    /**
     * Creates an instance of a JCE provider that supports native RSA via jnagmp.
     */
    public NativeRSAProvider() {
        super("native-rsa", 1.0, "SHA Digest with RSA Native implementation");
        put("Signature.SHA256withNativeRSA", NativeSHA256.class.getCanonicalName());
    }
}
