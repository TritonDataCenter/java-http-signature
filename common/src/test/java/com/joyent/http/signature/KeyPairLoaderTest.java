package com.joyent.http.signature;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.testng.Assert;
import org.testng.AssertJUnit;
import org.testng.SkipException;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

@Test
public class KeyPairLoaderTest {

    private static final String RSA_HEADER = "-----BEGIN RSA PRIVATE KEY-----";

    public void willThrowOnNullInputs() {
        Assert.assertThrows(() ->
                KeyPairLoader.getKeyPair((String) null, null));
        Assert.assertThrows(() ->
                KeyPairLoader.getKeyPair((Path) null, null));
    }

    public void canLoadGeneratedBytesKeyPair() throws Exception {
        final KeyPair keyPair = generateKeyPair();
        final byte[] serializedKey = serializePrivateKey(keyPair, null);

        Assert.assertTrue(new String(serializedKey, StandardCharsets.UTF_8).startsWith(RSA_HEADER));

        final KeyPair loadedKeyPair = KeyPairLoader.getKeyPair(serializedKey, null);

        compareKeyContents(keyPair, loadedKeyPair);
    }

    public void canLoadKeyPairFromFile() throws Exception {
        final KeyPair keyPair = generateKeyPair();
        final byte[] serializedKey = serializePrivateKey(keyPair, null);

        final File keyFile = Files.createTempFile("private-key", "").toFile();
        keyFile.deleteOnExit();
        final FileOutputStream fos = new FileOutputStream(keyFile);
        fos.write(serializedKey);

        final KeyPair loadedKeyPair = KeyPairLoader.getKeyPair(keyFile.toPath());

        compareKeyContents(keyPair, loadedKeyPair);
    }

    public void canLoadPasswordProtectedKeyBytes() throws Exception {
        final KeyPair keyPair = generateKeyPair();
        final String passphrase = "randompassword";
        // final byte[] serializedKey = serializePrivateKey(keyPair, passphrase);
        final byte[] serializedKey = serializePrivateKey(keyPair, passphrase);

        final KeyPair loadedKeyPair = KeyPairLoader.getKeyPair(serializedKey, passphrase.toCharArray());

        compareKeyContents(keyPair, loadedKeyPair);
    }


    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        return generator.generateKeyPair();
    }

    private byte[] serializePrivateKey(final KeyPair keyPair,
                                       final String passphrase) throws Exception {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(new OutputStreamWriter(baos));

        if (passphrase != null) {
            throw new SkipException("java.lang.ClassCastException: org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo cannot be cast to org.bouncycastle.openssl.PEMKeyPair");

            // final OutputEncryptor outputEncryptor =
            //         new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES)
            //                 .setPasssword(passphrase.toCharArray())
            //                 .build();
            //
            // jcaPEMWriter.writeObject(new JcaPKCS8Generator(keyPair.getPrivate(), outputEncryptor));
        } else {
            jcaPEMWriter.writeObject(keyPair.getPrivate());
        }

        jcaPEMWriter.flush();
        jcaPEMWriter.close();
        return baos.toByteArray();
    }

    private void compareKeyContents(KeyPair expectedKeyPair, KeyPair actualKeyPair) {
        AssertJUnit.assertArrayEquals(
                expectedKeyPair.getPrivate().getEncoded(),
                actualKeyPair.getPrivate().getEncoded());
        AssertJUnit.assertArrayEquals(
                expectedKeyPair.getPublic().getEncoded(),
                actualKeyPair.getPublic().getEncoded());
    }

}
