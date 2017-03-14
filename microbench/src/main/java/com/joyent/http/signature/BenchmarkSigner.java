/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

import java.io.IOException;
import java.security.KeyPair;
import java.util.concurrent.TimeUnit;

/* See http://openjdk.java.net/projects/code-tools/jmh/ for general
 * information on JMH and running benchmarks.  In general one would
 * "package" this module, and run `java -jar target/benchmark.jar`. */
@State(Scope.Thread)
@SuppressWarnings({"checkstyle:javadocmethod", "checkstyle:javadoctype", "checkstyle:javadocvariable",
            "checkstyle:visibilitymodifier"})
public abstract class BenchmarkSigner {
    protected KeyPair keyPair;
    protected String testKeyFingerprint;
    protected Signer signer;
    protected String verifyNow;
    protected String verifyHeader;
    private boolean firstSetup = true;

    @Param({"SHA1", "SHA256", "SHA512"})
    private String hash;


    @Param({"stdlib", "native.jnagmp"})
    private String providerCode;

    public abstract String getKeyCode();

    @Setup
    public void setup() throws IOException {
        testKeyFingerprint = SignerTestUtil.testKeyFingerprint(getKeyCode());
        keyPair = SignerTestUtil.testKeyPair(getKeyCode());
        signer = new Signer.Builder(keyPair).hash(hash).providerCode(providerCode).build();

        verifyNow = signer.defaultSignDateAsString();
        verifyHeader = signHeader(verifyNow);
        if (firstSetup) {
            System.out.println("\n#Signature-->Provider: " + signer.getSignature().getProvider().getName());
            firstSetup = false;
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public String signHeaderThroughput() {
        String now = signer.defaultSignDateAsString();
        return signHeader(now);
    }

    @Benchmark
    @BenchmarkMode(Mode.SampleTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public String signHeaderLatency() {
        String now = signer.defaultSignDateAsString();
        return signHeader(now);
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public boolean verifyHeaderThroughput() {
        return verifyHeader(verifyNow, verifyHeader);
    }

    @Benchmark
    @BenchmarkMode(Mode.SampleTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public boolean verifyHeaderLatency() {
        return verifyHeader(verifyNow, verifyHeader);
    }

    protected String signHeader(final String now) {
        String authzHeader = signer.createAuthorizationHeader("bench", testKeyFingerprint, keyPair, now);
        return authzHeader;
    }

    protected boolean verifyHeader(final String ts, final String header) {
        return signer.verifyAuthorizationHeader(keyPair, header, ts);

    }
}
