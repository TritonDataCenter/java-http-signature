/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

import org.openjdk.jmh.annotations.Param;


@SuppressWarnings({"checkstyle:javadocmethod", "checkstyle:javadoctype", "checkstyle:javadocvariable"})
public class BenchmarkECDSASigner extends BenchmarkSigner {
    @Param({"SHA256", "SHA384", "SHA512"})
    private String hash;

    @Param({"stdlib"})
    private String providerCode;

    public String getKeyCode() {
        return "ecdsa_256";
    }
}
