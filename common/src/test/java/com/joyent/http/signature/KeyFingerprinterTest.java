/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;


public class KeyFingerprinterTest {

    @Test
    public void rsaMd5() throws Exception {
        Assert.assertEquals(KeyFingerprinter.md5Fingerprint(SignerTestUtil.testKeyPair("rsa_1024")),
                             SignerTestUtil.testKeyMd5Fingerprint("rsa_1024"));
        Assert.assertEquals(KeyFingerprinter.md5Fingerprint(SignerTestUtil.testKeyPair("rsa_2048")),
                             SignerTestUtil.testKeyMd5Fingerprint("rsa_2048"));
        Assert.assertEquals(KeyFingerprinter.md5Fingerprint(SignerTestUtil.testKeyPair("rsa_3072")),
                             SignerTestUtil.testKeyMd5Fingerprint("rsa_3072"));
        Assert.assertEquals(KeyFingerprinter.md5Fingerprint(SignerTestUtil.testKeyPair("rsa_4096")),
                             SignerTestUtil.testKeyMd5Fingerprint("rsa_4096"));
    }

    @Test
    public void rsaSha256() throws Exception {
        Assert.assertEquals(KeyFingerprinter.sha256Fingerprint(SignerTestUtil.testKeyPair("rsa_1024")),
                             SignerTestUtil.testKeySha256Fingerprint("rsa_1024"));
        Assert.assertEquals(KeyFingerprinter.sha256Fingerprint(SignerTestUtil.testKeyPair("rsa_2048")),
                             SignerTestUtil.testKeySha256Fingerprint("rsa_2048"));
        Assert.assertEquals(KeyFingerprinter.sha256Fingerprint(SignerTestUtil.testKeyPair("rsa_3072")),
                             SignerTestUtil.testKeySha256Fingerprint("rsa_3072"));
        Assert.assertEquals(KeyFingerprinter.sha256Fingerprint(SignerTestUtil.testKeyPair("rsa_4096")),
                             SignerTestUtil.testKeySha256Fingerprint("rsa_4096"));
    }

    @Test
    public void dsaMd5() throws Exception {
         Assert.assertEquals(KeyFingerprinter.md5Fingerprint(SignerTestUtil.testKeyPair("dsa_1024")),
                             SignerTestUtil.testKeyMd5Fingerprint("dsa_1024"));
    }

    @Test
    public void dsaSha256() throws Exception {
         Assert.assertEquals(KeyFingerprinter.sha256Fingerprint(SignerTestUtil.testKeyPair("dsa_1024")),
                             SignerTestUtil.testKeySha256Fingerprint("dsa_1024"));
    }

    @Test
    public void ecdsaMd5() throws Exception {
        Assert.assertEquals(KeyFingerprinter.md5Fingerprint(SignerTestUtil.testKeyPair("ecdsa_256")),
                            SignerTestUtil.testKeyMd5Fingerprint("ecdsa_256"));
        Assert.assertEquals(KeyFingerprinter.md5Fingerprint(SignerTestUtil.testKeyPair("ecdsa_384")),
                            SignerTestUtil.testKeyMd5Fingerprint("ecdsa_384"));
        Assert.assertEquals(KeyFingerprinter.md5Fingerprint(SignerTestUtil.testKeyPair("ecdsa_521")),
                            SignerTestUtil.testKeyMd5Fingerprint("ecdsa_521"));
    }

    @Test
    public void ecdsaSha256() throws Exception {
        Assert.assertEquals(KeyFingerprinter.sha256Fingerprint(SignerTestUtil.testKeyPair("ecdsa_256")),
                            SignerTestUtil.testKeySha256Fingerprint("ecdsa_256"));
        Assert.assertEquals(KeyFingerprinter.sha256Fingerprint(SignerTestUtil.testKeyPair("ecdsa_384")),
                            SignerTestUtil.testKeySha256Fingerprint("ecdsa_384"));
        Assert.assertEquals(KeyFingerprinter.sha256Fingerprint(SignerTestUtil.testKeyPair("ecdsa_521")),
                            SignerTestUtil.testKeySha256Fingerprint("ecdsa_521"));
    }

    @Test
    public void testVerifyDefault() throws Exception {
        Assert.assertTrue(KeyFingerprinter.verifyFingerprint(SignerTestUtil.testKeyPair("rsa_2048"),
                                                             SignerTestUtil.testKeyMd5Fingerprint("rsa_2048")));
        Assert.assertFalse(KeyFingerprinter.verifyFingerprint(SignerTestUtil.testKeyPair("rsa_2048"),
                                                              "1" + SignerTestUtil.testKeyMd5Fingerprint("rsa_2048")));
    }

    @Test
    public void testVerifyMd5() throws Exception {
        Assert.assertTrue(KeyFingerprinter.verifyFingerprint(SignerTestUtil.testKeyPair("rsa_2048"),
                                                             "MD5:" + SignerTestUtil.testKeyMd5Fingerprint("rsa_2048")));
        Assert.assertFalse(KeyFingerprinter.verifyFingerprint(SignerTestUtil.testKeyPair("rsa_2048"),
                                                              "MD5:foo"));
    }

    @Test
    public void testVerifySha256() throws Exception {
        Assert.assertTrue(KeyFingerprinter.verifyFingerprint(SignerTestUtil.testKeyPair("rsa_2048"),
                                                             "SHA256:" + SignerTestUtil.testKeySha256Fingerprint("rsa_2048")));
        Assert.assertFalse(KeyFingerprinter.verifyFingerprint(SignerTestUtil.testKeyPair("rsa_2048"),
                                                              "SHA256:LP3pWCEhg6rdmE05GhUKbZ7uOZqsJd0sK0AR3sVoMq4"));
    }
}
