package com.joyent.http.signature;

import java.security.Provider;

/**
 * Created by elijah on 1/2/16.
 */
public class NativeRSAProvider extends Provider {
    public NativeRSAProvider() {
        super("native-rsa", 1.0, "SHA Digest with RSA Native implementation");
        put("Signature.SHA256withNativeRSA", NativeSHA256.class.getCanonicalName());
    }
}
