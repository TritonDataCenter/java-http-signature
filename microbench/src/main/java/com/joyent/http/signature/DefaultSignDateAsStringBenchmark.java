/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;

import java.io.IOException;
import java.security.KeyPair;


@State(Scope.Benchmark)
@SuppressWarnings({"checkstyle:javadocmethod", "checkstyle:javadoctype", "checkstyle:javadocvariable",
            "checkstyle:magicnumber"})
public class DefaultSignDateAsStringBenchmark  {

    private KeyPair keyPair;
    private String testKeyFingerprint;
    private Signer signer;
    private boolean firstSetup = true;

    @Setup
    public void setup() throws IOException {
        testKeyFingerprint = SignerTestUtil.testKeyMd5Fingerprint("rsa_1024");
        keyPair = SignerTestUtil.testKeyPair("rsa_1024");
        signer = new Signer.Builder(keyPair).hash("SHA256").providerCode("stdlib").build();

        if (firstSetup) {
            System.out.println("\n#Signature-->Provider: " + signer.getSignature().getProvider().getName());
            firstSetup = false;
        }
    }

    @Benchmark
    @Threads(1)
    public String thread1() {
        return signer.defaultSignDateAsString();
    }

    @Benchmark
    @Threads(4)
    public String thread4() {
        return signer.defaultSignDateAsString();
    }

    @Threads(8)
    public String thread8() {
        return signer.defaultSignDateAsString();
    }

    @Benchmark
    @Threads(64)
    public String thread64() {
        return signer.defaultSignDateAsString();
    }

}
