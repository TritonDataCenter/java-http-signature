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
public class BenchmarkKeyFingerprinter {
    protected KeyPair keyPair;

    @Param({"dsa_1024", "rsa_2048", "ecdsa_256"})
    private String keyCode;

    @Setup
    public void setup() throws IOException {
        keyPair = SignerTestUtil.testKeyPair(keyCode);
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public String fingerprintThroughput() {
        String fingerprint = KeyFingerprinter.md5Fingerprint(keyPair);
        return fingerprint;
    }

    @Benchmark
    @BenchmarkMode(Mode.SampleTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    public String fingerprintLatency() {
        String fingerprint = KeyFingerprinter.md5Fingerprint(keyPair);
        return fingerprint;
    }
}
