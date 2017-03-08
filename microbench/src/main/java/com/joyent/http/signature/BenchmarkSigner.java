/*
 * Copyright (c) 2013-2017, Joyent, Inc. All rights reserved.
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
public class BenchmarkSigner {
    private String testKeyFingerprint;
    private KeyPair keyPair;
    private Signer signer;
    private String verifyNow;
    private String verifyHeader;

    @Param({"vanilla", "native"})
    private String signType;

    @Setup
    public void setup() throws IOException {
        switch (signType) {
        case "vanilla":
            signer = new Signer(false);
            break;
        case "native":
            signer = new Signer(true);
            break;
        default:
            throw new IllegalArgumentException();
        }
        testKeyFingerprint = SignerTestUtil.testKeyFingerprint;
        keyPair = SignerTestUtil.testKeyPair(signer);

        verifyNow = signer.defaultSignDateAsString();
        verifyHeader = signHeader(verifyNow);
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

    private String signHeader(final String now) {
        String authzHeader = signer.createAuthorizationHeader("bench", testKeyFingerprint, keyPair, now);
        return authzHeader;
    }

    private boolean verifyHeader(final String ts, final String header) {
        return signer.verifyAuthorizationHeader(keyPair, header, ts);

    }
}
