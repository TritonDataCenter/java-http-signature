package com.joyent.http.signature;

import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.testng.Assert;
import org.testng.AssertJUnit;
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
import java.util.UUID;

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

        final KeyPair loadedKeyPair = KeyPairLoader.getKeyPair(keyFile);

        compareKeyContents(keyPair, loadedKeyPair);
    }

    public void canLoadPasswordProtectedKeyBytes() throws Exception {
        final KeyPair keyPair = generateKeyPair();
        final String passphrase = UUID.randomUUID().toString();
        final byte[] serializedKey = serializePrivateKey(keyPair, passphrase);

        Assert.assertTrue(new String(serializedKey, StandardCharsets.UTF_8).startsWith(RSA_HEADER));

        final KeyPair loadedKeyPair = KeyPairLoader.getKeyPair(serializedKey, passphrase.toCharArray());

        compareKeyContents(keyPair, loadedKeyPair);
    }

    public void canLoadPasswordProtectedKeyFromFile() throws Exception {
        final KeyPair keyPair = generateKeyPair();
        final String passphrase = UUID.randomUUID().toString();
        final byte[] serializedKey = serializePrivateKey(keyPair, passphrase);

        Assert.assertTrue(new String(serializedKey, StandardCharsets.UTF_8).startsWith(RSA_HEADER));

        final File keyFile = Files.createTempFile("private-key-with-passphrase", "").toFile();
        keyFile.deleteOnExit();
        final FileOutputStream fos = new FileOutputStream(keyFile);
        fos.write(serializedKey);

        final KeyPair loadedKeyPair = KeyPairLoader.getKeyPair(keyFile, passphrase.toCharArray());

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
            final PEMEncryptor pemEncryptor = new JcePEMEncryptorBuilder("AES-128-CBC").build(passphrase.toCharArray());
            final JcaMiscPEMGenerator pemGenerator = new JcaMiscPEMGenerator(keyPair.getPrivate(), pemEncryptor);
            jcaPEMWriter.writeObject(pemGenerator);
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
