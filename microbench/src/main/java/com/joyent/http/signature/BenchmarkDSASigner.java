/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

import org.openjdk.jmh.annotations.Param;

import static com.joyent.http.signature.KeyPairLoader.PROVIDER_BOUNCY_CASTLE;
import static com.joyent.http.signature.KeyPairLoader.PROVIDER_PKCS11_NSS;


@SuppressWarnings({"checkstyle:javadocmethod", "checkstyle:javadoctype", "checkstyle:javadocvariable"})
public class BenchmarkDSASigner extends BenchmarkSigner {
    @Param({"SHA1", "SHA256"})
    private String hash;

    @Param({"stdlib"})
    private String providerCode;

    @Param({PROVIDER_PKCS11_NSS, PROVIDER_BOUNCY_CASTLE})
    private String keyProviderCode;

    @Override
    public String getKeyCode() {
        return "dsa_1024";
    }
}
