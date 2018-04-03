/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

import org.testng.Assert;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

/**
 * Utility stress test class for comparing generated fingerprints to
 * openssh on randomly generated keys.  For example, to generate 1000
 * RSA keys and compare the KeyFingerprinter result to ssh-keygen -l.
 */
public class KeyFingerprinterIntegrationCycle {

    private final String keyType;
    private final int bits;
    private final int iterations;
    private final Path tmpDir;

    public KeyFingerprinterIntegrationCycle(String keyType, int bits, int iterations) {
        this.keyType = keyType;
        this.bits = bits;
        this.iterations = iterations;
        try {
            this.tmpDir = Files.createTempDirectory("keys-");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        System.out.println(this.tmpDir);
    }

    private String privateFileName(int iteration) {
        return tmpDir.toString() + File.separator + iteration;
    }

    public void keygen(int iteration) throws IOException, InterruptedException {
        Process p = Runtime.getRuntime().exec(new String[] {
                "ssh-keygen", "-t", keyType, "-b", Integer.toString(bits), "-f", privateFileName(iteration),  "-P", ""});
        if (p.waitFor() > 0) {
            throw new RuntimeException("gen cmd failed: " + p);
        }
    }

    // NOTE: need -E md5 for openssh > 6.7
    public String readMd5Fingerprint(int iteration) throws IOException, InterruptedException {
        Process p = Runtime.getRuntime().exec(new String[] {
                "ssh-keygen", "-l", "-f", privateFileName(iteration) + ".pub"});
        if (p.waitFor() > 0) {
            throw new RuntimeException("check cmd failed: " + p);
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream(),
                StandardCharsets.US_ASCII));
        String line = reader.readLine();
        return line.split(" ")[1];
    }

    public void doIteration(int iteration) throws IOException, InterruptedException {
        keygen(iteration);
        String expected = readMd5Fingerprint(iteration);
        String fingerprint = KeyFingerprinter.md5Fingerprint(KeyPairLoader.getKeyPair(Paths.get(privateFileName(iteration))));
        try {
            Assert.assertEquals(fingerprint, expected);
        } catch (AssertionError e) {
            System.out.println("fname: " + privateFileName(iteration));
            throw e;
        }
    }

    public void run() {
        for (int i = 0; i< iterations; i++) {
            try {
                doIteration(i);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        try (Stream<Path> paths = Files.walk(tmpDir)){
            paths.map(Path::toFile)
                .sorted((o1, o2) -> -o1.compareTo(o2))
                .forEach(File::delete);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // Example:
    // mvn -Dexec.mainClass=com.joyent.http.signature.KeyFingerprinterIntegrationCycle -Dexec.classpathScope=test test-compile exec:java -Dexec.args="rsa 10"
    public static void main(String[] args) {
        String keyType = args[0];
        int bits = Integer.parseInt(args[1]);
        int iterations = Integer.parseInt(args[2]);
        KeyFingerprinterIntegrationCycle test = new KeyFingerprinterIntegrationCycle(keyType, bits, iterations);
        test.run();
    }
}
