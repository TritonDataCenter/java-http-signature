/**
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */
package com.joyent.http.signature;

import com.joyent.http.signature.crypto.NativeRSAProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Objects;
import java.util.TimeZone;

/**
 *  HTTP authorization signer. This adheres to the specs of the node-http-signature spec.
 *
 * @see <a href="http://tools.ietf.org/html/draft-cavage-http-signatures-05">Signing HTTP Messages</a>
 * @see <a href="https://github.com/joyent/java-manta/blob/b2a180ff8a3ec3795ccc258904888f8305619756/src/main/java/com/joyent/manta/client/crypto/HttpSigner.java">Original Version</a>
 * @author Yunong Xiao
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 * @since 1.0.0
 */
public final class HttpSignerUtils {
    /**
     * HTTP header sent to identify a unique request.
     */
    public static final String X_REQUEST_ID_HEADER = "x-request-id";

    /**
     * The format for the http date header.
     */
    public static final DateFormat DATE_FORMAT = new SimpleDateFormat("EEE MMM d HH:mm:ss yyyy zzz");

    /**
     * The template for the Authorization header.
     */
    public static final String AUTHZ_HEADER =
            "Signature keyId=\"/%s/keys/%s\",algorithm=\"rsa-sha256\",signature=\"%s\"";

    /**
     * The template for the authorization signing signing string.
     */
    public static final String AUTHZ_SIGNING_STRING = "date: %s";

    /**
     * The prefix for the signature component of the authorization header.
     */
    public static final String AUTHZ_PATTERN = "signature=\"";

    /**
     * Signing algorithm implemented entirely in the JVM.
     */
    public static final String SIGNING_JVM_ALGORITHM = "SHA256withRSA";

    /**
     * Signing algorithm that uses JNA extents to libgmp for improved performance.
     */
    public static final String SIGNING_NATIVE_ALGORITHM = "SHA256withNativeRSA";

    /**
     * Cryptographic signature used for signing requests.
     */
    public static final Signature SIGNATURE = findBestSignature();

    /**
     * The key format CONVERTER to use when reading key pairs.
     */
    private static final JcaPEMKeyConverter CONVERTER =
            new JcaPEMKeyConverter().setProvider("BC");

    /**
     * Utility class not intended for direct instantiation.
     */
    private HttpSignerUtils() {
    }

    /**
     * Attempts to use a signing algorithm that is implemented using native code.
     * If that fails, it falls back to the pure JVM implementation.
     * @return a SHA256 signing algorithm
     */
    public static Signature findBestSignature() {
        final String os = System.getProperty("os.name").toLowerCase();
        final String arch = System.getProperty("os.arch").toLowerCase();

        final boolean nativeSupported =
                (os.equals("linux") && arch.equals("amd64"))
             || (os.equals("mac os x") && arch.equals("x86_64"));

        // We only support native RSA on 64-bit x86 Linux and OS X
        if (!nativeSupported) {
            try {
                return Signature.getInstance(SIGNING_JVM_ALGORITHM);
            } catch (NoSuchAlgorithmException nsae) {
                throw new CryptoException(nsae);
            }
        }

        try {
            final Provider provider = new NativeRSAProvider();
            return Signature.getInstance(SIGNING_NATIVE_ALGORITHM, provider);
            // if ANYTHING goes wrong, we default to the JVM implementation of the signing algo
        } catch (Exception e) {
            try {
                return Signature.getInstance(SIGNING_JVM_ALGORITHM);
            } catch (NoSuchAlgorithmException nsae) {
                throw new CryptoException(nsae);
            }
        }
    }

    /**
     * Read KeyPair located at the specified path.
     *
     * @param keyPath The path to the rsa key
     * @return public-private keypair object
     * @throws IOException If unable to read the private key from the file
     */
    public static KeyPair getKeyPair(final Path keyPath) throws IOException {
        if (keyPath == null) {
            throw new FileNotFoundException("No key file path specified");
        }

        if (!Files.exists(keyPath)) {
            throw new FileNotFoundException(
                    String.format("No key file available at path: %s", keyPath));
        }

        if (!Files.isReadable(keyPath)) {
            throw new IOException(
                    String.format("Can't read key file from path: %s", keyPath));
        }

        try (final InputStream is = Files.newInputStream(keyPath)) {
            return getKeyPair(is, null);
        }
    }

    /**
     * Read KeyPair from a string, optionally using password.
     *
     * @param privateKeyContent private key content as a string
     * @param password password associated with key
     * @return public-private keypair object
     * @throws IOException If unable to read the private key from the string
     */
    public static KeyPair getKeyPair(final String privateKeyContent, final char[] password) throws IOException {
        byte[] pKeyBytes = privateKeyContent.getBytes();

        return getKeyPair(pKeyBytes, password);
    }

    /**
     * Read KeyPair from a string, optionally using password.
     *
     * @param pKeyBytes private key content as a byte array
     * @param password password associated with key
     * @return public-private keypair object
     * @throws IOException If unable to read the private key from the string
     */
    public static KeyPair getKeyPair(final byte[] pKeyBytes, final char[] password) throws IOException {
        if (pKeyBytes == null) {
            throw new IllegalArgumentException("pKeyBytes must be present");
        }

        try (InputStream is = new ByteArrayInputStream(pKeyBytes)) {
            return getKeyPair(is, password);
        }
    }

    /**
     * Read KeyPair from an input stream, optionally using password.
     *
     * @param is private key content as a stream
     * @param password password associated with key
     * @return public/private keypair object
     * @throws IOException If unable to read the private key from the string
     */
    public static KeyPair getKeyPair(final InputStream is,
                                     final char[] password) throws IOException {
        try (final InputStreamReader isr = new InputStreamReader(is);
             final BufferedReader br = new BufferedReader(isr);
             final PEMParser pemParser = new PEMParser(br)) {

            if (password == null) {
                Security.addProvider(new BouncyCastleProvider());
                final Object object = pemParser.readObject();
                return CONVERTER.getKeyPair((PEMKeyPair) object);
            } else {
                PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password);

                Object object = pemParser.readObject();

                final KeyPair kp;
                if (object instanceof PEMEncryptedKeyPair) {
                    kp = CONVERTER.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
                } else {
                    kp = CONVERTER.getKeyPair((PEMKeyPair) object);
                }

                return kp;
            }
        }
    }

    /**
     * Generate a signature for an authorization HTTP header using the
     * current time as a timestamp.
     *
     * @param login Account/login name
     * @param fingerprint RSA key fingerprint
     * @param keyPair RSA public/private keypair
     * @return value to Authorization header
     */
    public static String createAuthorizationHeader(final String login,
                                                   final String fingerprint,
                                                   final KeyPair keyPair) {
        return createAuthorizationHeader(login, fingerprint, keyPair,
                defaultSignDateAsString());
    }

    /**
     * Generate a signature for an authorization HTTP header.
     *
     * @param login Account/login name
     * @param fingerprint RSA key fingerprint
     * @param keyPair RSA public/private keypair
     * @param date Date to be converted to a RFC 822 compliant string
     * @return value to Authorization header
     */

    public static String createAuthorizationHeader(final String login,
                                                   final String fingerprint,
                                                   final KeyPair keyPair,
                                                   final Date date) {
        final String stringDate;

        if (date == null) {
            stringDate = defaultSignDateAsString();
        } else {
            stringDate = DATE_FORMAT.format(date);
        }

        return createAuthorizationHeader(login, fingerprint, keyPair,
                stringDate);
    }

    /**
     * Generate a signature for an authorization HTTP header.
     *
     * @param login Account/login name
     * @param fingerprint RSA key fingerprint
     * @param keyPair RSA public/private keypair
     * @param date Date as RFC 822 compliant string
     * @return value to Authorization header
     */
    public static String createAuthorizationHeader(final String login,
                                                   final String fingerprint,
                                                   final KeyPair keyPair,
                                                   final String date) {
        Objects.requireNonNull(login, "Login must be present");
        Objects.requireNonNull(fingerprint, "Fingerprint must be present");
        Objects.requireNonNull(keyPair, "Keypair must be present");

        try {
            SIGNATURE.initSign(keyPair.getPrivate());
            final String signingString = String.format(AUTHZ_SIGNING_STRING, date);
            SIGNATURE.update(signingString.getBytes("UTF-8"));
            final byte[] signedDate = SIGNATURE.sign();
            final byte[] encodedSignedDate = Base64.encode(signedDate);

            return String.format(AUTHZ_HEADER, login, fingerprint,
                    new String(encodedSignedDate));
        } catch (final InvalidKeyException e) {
            throw new CryptoException("invalid key", e);
        } catch (final SignatureException e) {
            throw new CryptoException("invalid signature", e);
        } catch (final UnsupportedEncodingException e) {
            throw new CryptoException("invalid encoding", e);
        }
    }

    /**
     * Cryptographically signs an any data input.
     *
     * @param login Account/login name
     * @param fingerprint RSA key fingerprint
     * @param keyPair RSA public/private keypair
     * @param data data to be signed
     * @return signed value of data
     */
    public static byte[] sign(final String login,
                              final String fingerprint,
                              final KeyPair keyPair,
                              final byte[] data) {
        Objects.requireNonNull(login, "Login must be present");
        Objects.requireNonNull(fingerprint, "Fingerprint must be present");
        Objects.requireNonNull(keyPair, "Keypair must be present");
        Objects.requireNonNull(data, "Data must be present");

        try {
            SIGNATURE.initSign(keyPair.getPrivate());
            SIGNATURE.update(data);
            return SIGNATURE.sign();
        } catch (final InvalidKeyException e) {
            throw new CryptoException("invalid key", e);
        } catch (final SignatureException e) {
            throw new CryptoException("invalid signature", e);
        }
    }

    /**
     * Cryptographically signs an any data input.
     *
     * @param login Account/login name
     * @param fingerprint RSA key fingerprint
     * @param keyPair RSA public/private keypair
     * @param data data that was signed
     * @param signedData data to verify against signature
     * @return signed value of data
     */
    public static boolean verify(final String login,
                                 final String fingerprint,
                                 final KeyPair keyPair,
                                 final byte[] data,
                                 final byte[] signedData) {
        Objects.requireNonNull(login, "Login must be present");
        Objects.requireNonNull(fingerprint, "Fingerprint must be present");
        Objects.requireNonNull(keyPair, "Keypair must be present");
        Objects.requireNonNull(signedData, "Data must be present");

        try {
            SIGNATURE.initVerify(keyPair.getPublic());
            SIGNATURE.update(data);
            return SIGNATURE.verify(signedData);

        } catch (final InvalidKeyException e) {
            throw new CryptoException("invalid key", e);
        } catch (final SignatureException e) {
            throw new CryptoException("invalid signature", e);
        }
    }

    /**
     * The current timestamp in UTC.
     * @return current timestamp in UTC.
     */
    private static Date defaultSignDate() {
        return Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTime();
    }

    /**
     * The current timestamp in UTC as a RFC 822 compliant string.
     * @return Date as RFC 822 compliant string
     */
    public static String defaultSignDateAsString() {
        return DATE_FORMAT.format(defaultSignDate());
    }

    /**
     * Verify a signed HTTP Authorization header.
     *
     * @param keyPair RSA public/private keypair
     * @param authzHeader authorization header value
     * @param date Date as RFC 822 compliant string
     * @return True if the request is valid, false if not.
     * @throws CryptoException If unable to verify the request.
     */
    public static boolean verifyAuthorizationHeader(final KeyPair keyPair,
                                             final String authzHeader,
                                             final String date) {
        Objects.requireNonNull(keyPair, "Keypair must be present");
        Objects.requireNonNull(authzHeader, "AuthzHeader must be present");
        Objects.requireNonNull(date, "Date must be present");

        String myDate = String.format(AUTHZ_SIGNING_STRING, date);

        try {
            SIGNATURE.initVerify(keyPair.getPublic());

            final int startIndex = authzHeader.indexOf(AUTHZ_PATTERN);
            if (startIndex == -1) {
                throw new CryptoException(
                        String.format("invalid authorization header %s", authzHeader));
            }

            final String encodedSignedDate = authzHeader.substring(startIndex + AUTHZ_PATTERN.length(),
                    authzHeader.length() - 1);
            final byte[] signedDate = Base64.decode(encodedSignedDate.getBytes("UTF-8"));

            SIGNATURE.update(myDate.getBytes("UTF-8"));
            return SIGNATURE.verify(signedDate);

        } catch (final InvalidKeyException e) {
            throw new CryptoException("invalid key", e);
        } catch (final SignatureException e) {
            throw new CryptoException("invalid signature", e);
        } catch (final UnsupportedEncodingException e) {
            throw new CryptoException("invalid encoding", e);
        }
    }
}
