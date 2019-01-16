/*
 * Copyright (c) 2013-2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

import com.joyent.http.signature.crypto.NativeRSAProvider;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;
import java.util.Objects;

/**
 *  HTTP authorization signer. This adheres to the specs of the node-http-signature spec.
 *
 * @see <a href="http://tools.ietf.org/html/draft-cavage-http-signatures-05">Signing HTTP Messages</a>
 * @see <a href="https://github.com/joyent/java-manta/blob/b2a180ff8a3ec3795ccc258904888f8305619756/src/main/java/com/joyent/manta/client/crypto/HttpSigner.java">Original Version</a>
 * @author Yunong Xiao
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 * @since 1.0.0
 */
public class Signer {
    /**
     * The format for the http date header.
     *
     * @deprecated In java8 and later a RFC appropriate format is
     * defined in the standard library using modern classes.
     */
    @Deprecated
    @SuppressWarnings("DateFormatConstant")
    public static final DateFormat DATE_FORMAT = new SimpleDateFormat(
            "EEE MMM d HH:mm:ss yyyy zzz", Locale.ENGLISH);

    /**
     * The template for the Authorization header.
     */
    private static final String AUTHZ_HEADER =
            "Signature keyId=\"/%s/keys/%s\",algorithm=\"%s\",signature=\"%s\"";

    /**
     * The template for the authorization signing signing string.
     */
    private static final String AUTHZ_SIGNING_STRING = "date: %s";

    /**
     * The prefix for the signature component of the authorization header.
     */
    private static final String AUTHZ_PATTERN = "signature=\"";

    /**
     * Cryptographic signature used for signing requests.
     */
    private final Signature signature;

    /**
     *  Private field with the computed http header algorithm.
     */
    private final String httpHeaderAlgorithm;

    /**
     * Creates a new instance of the class and enables native code acceleration of
     * cryptographic signing by default.
     *
     * @deprecated Prefer use of {@link Signer.Builder}
     */
    @Deprecated
    public Signer() {
        this(true);
    }

    /**
     * Creates a new instance of the class.
     *
     * @param useNativeCodeToSign true to enable native code acceleration of cryptographic singing
     *
     * @deprecated Prefer use of {@link Signer.Builder}
     */
    @Deprecated
    @SuppressWarnings("checkstyle:avoidinlineconditionals")
    public Signer(final boolean useNativeCodeToSign) {
        this(new Builder("RSA").providerCode(useNativeCodeToSign ? "native.jnagmp" : "stdlib"));
    }

    /**
     * {@link Signer.Builder} This is public (a difference from the
     * normal Builder pattern) for use by {@link ThreadLocalSigner}.
     *
     * @param builder {@link Signer.Builder}
     */
    public Signer(final Builder builder) {
        Provider provider = builder.algHelper.makeProvider(builder.providerCode);
        httpHeaderAlgorithm = builder.httpHeaderAlgorithm();
        if (provider == null) {
            try {
                signature = Signature.getInstance(builder.javaStandardName(provider));
            } catch (NoSuchAlgorithmException nsae) {
                throw new CryptoException(nsae);
            }
        } else {
            try {
                signature = Signature.getInstance(builder.javaStandardName(provider), provider);
            } catch (NoSuchAlgorithmException nsae) {
                throw new CryptoException(nsae);
            }
        }
    }

    /**
     * @see KeyPairLoader#getKeyPair
     *
     * @param keyPath The path to the key
     * @return public-private keypair object
     * @throws IOException If unable to read the private key from the file
     *
     * @deprecated Since a {@code KeyPair} is needed to instantiate,
     * is is now backwards for this to be an instance method.
     */
    @Deprecated
    public KeyPair getKeyPair(final Path keyPath) throws IOException {
        return KeyPairLoader.getKeyPair(keyPath);
    }

    /**
     * @see KeyPairLoader#getKeyPair
     *
     * @param privateKeyContent private key content as a string
     * @param password password associated with key
     * @return public-private keypair object
     * @throws IOException If unable to read the private key from the string
     *
     * @deprecated Since a {@code KeyPair} is needed to instantiate,
     * is is now backwards for this to be an instance method.
     */
    @Deprecated
    public KeyPair getKeyPair(final String privateKeyContent, final char[] password) throws IOException {
        return KeyPairLoader.getKeyPair(privateKeyContent, password);
    }

    /**
     * @see KeyPairLoader#getKeyPair
     *
     * @param pKeyBytes private key content as a byte array
     * @param password password associated with key
     * @return public-private keypair object
     * @throws IOException If unable to read the private key from the string
     *
     * @deprecated Since a {@code KeyPair} is needed to instantiate,
     * is is now backwards for this to be an instance method.
     */
    @Deprecated
    public KeyPair getKeyPair(final byte[] pKeyBytes, final char[] password) throws IOException {
        return KeyPairLoader.getKeyPair(pKeyBytes, password);
    }

    /**
     * @see KeyPairLoader#getKeyPair
     *
     * @param is private key content as a stream
     * @param password password associated with key
     * @return public/private keypair object
     * @throws IOException If unable to read the private key from the string
     *
     * @deprecated Since a {@code KeyPair} is needed to instantiate,
     * is is now backwards for this to be an instance method.
     */
    @Deprecated
    public KeyPair getKeyPair(final InputStream is,
                              final char[] password) throws IOException {
        return KeyPairLoader.getKeyPair(is, password);
    }

    /**
     * Generate a signature for an authorization HTTP header using the
     * current time as a timestamp.
     *
     * @param login Account/login name
     * @param fingerprint key fingerprint (ignored)
     * @param keyPair public/private keypair
     * @return value to Authorization header
     *
     * @deprecated The fingerprint is now calculated from the given key.
     */
    @Deprecated
    public String createAuthorizationHeader(final String login,
                                            final String fingerprint,
                                            final KeyPair keyPair) {
        return createAuthorizationHeader(login, keyPair, defaultSignDateAsString());
    }

    /**
     * Generate a signature for an authorization HTTP header using the
     * current time as a timestamp.
     *
     * @param login Account/login name
     * @param keyPair public/private keypair
     * @return value to Authorization header
     */
    public String createAuthorizationHeader(final String login,
                                            final KeyPair keyPair) {
        return createAuthorizationHeader(login, keyPair, defaultSignDateAsString());
    }

    /**
     * Generate a signature for an authorization HTTP header.
     *
     * @param login Account/login name
     * @param fingerprint key fingerprint (ignored)
     * @param keyPair public/private keypair
     * @param date Date to be converted to a RFC 822 compliant string
     * @return value to Authorization header
     *
     * @deprecated The fingerprint is now calculated from the given key.
     */
    @Deprecated
    public String createAuthorizationHeader(final String login,
                                            final String fingerprint,
                                            final KeyPair keyPair,
                                            final Date date) {
        return createAuthorizationHeader(login, keyPair, date);
    }

    /**
     * Generate a signature for an authorization HTTP header.
     *
     * @param login Account/login name
     * @param keyPair public/private keypair
     * @param date DateTime to be converted to a RFC 822 compliant string
     * @return value to Authorization header
     *
     * @deprecated Prefer ZonedDateTime to java.util.Date
     */
    @Deprecated
    public String createAuthorizationHeader(final String login,
                                            final KeyPair keyPair,
                                            final Date date) {
        final ZonedDateTime zdt;
        if (date == null) {
            zdt = null;
        } else {
            zdt = ZonedDateTime.ofInstant(date.toInstant(), ZoneOffset.UTC);
        }

        return createAuthorizationHeader(login, keyPair, zdt);
    }

    /**
     * Generate a signature for an authorization HTTP header.
     *
     * @param login Account/login name
     * @param keyPair public/private keypair
     * @param dateTime DateTime to be converted to a RFC 822 compliant string
     * @return value to Authorization header
     */
    public String createAuthorizationHeader(final String login,
                                            final KeyPair keyPair,
                                            final ZonedDateTime dateTime) {
        final String stringDate;

        if (dateTime == null) {
            stringDate = defaultSignDateAsString();
        } else {
            stringDate = DateTimeFormatter.RFC_1123_DATE_TIME.format(dateTime);
        }

        return createAuthorizationHeader(login, keyPair, stringDate);
    }

    /**
     * Generate a signature for an authorization HTTP header.
     *
     * @param login Account/login name
     * @param fingerprint key fingerprint (ignored)
     * @param keyPair public/private keypair
     * @param date Date as RFC 822 compliant string
     * @return value to Authorization header
     *
     * @deprecated The fingerprint is now calculated from the given key.
     */
    @Deprecated
    public String createAuthorizationHeader(final String login,
                                            final String fingerprint,
                                            final KeyPair keyPair,
                                            final String date) {
        Objects.requireNonNull(login, "Login must be present");
        Objects.requireNonNull(keyPair, "Keypair must be present");
        return createAuthorizationHeader(login, keyPair, date);
    }


    /**
     * Generate a signature for an authorization HTTP header.
     *
     * @param login Account/login name
     * @param keyPair public/private keypair
     * @param date Date as RFC 822 compliant string
     * @return value to Authorization header
     */
    public String createAuthorizationHeader(final String login,
                                            final KeyPair keyPair,
                                            final String date) {
        Objects.requireNonNull(login, "Login must be present");
        Objects.requireNonNull(keyPair, "Keypair must be present");

        try {
            signature.initSign(keyPair.getPrivate());
            final String signingString = String.format(AUTHZ_SIGNING_STRING, date);
            signature.update(signingString.getBytes(StandardCharsets.UTF_8));
            final byte[] signedDate = signature.sign();
            final byte[] encodedSignedDate = Base64.encode(signedDate);
            final String fingerprint = KeyFingerprinter.md5Fingerprint(keyPair);

            return String.format(AUTHZ_HEADER, login, fingerprint, httpHeaderAlgorithm,
                    new String(encodedSignedDate, StandardCharsets.US_ASCII));
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
     * @param fingerprint key fingerprint (ignored)
     * @param keyPair public/private keypair
     * @param data data to be signed
     * @return signed value of data
     *
     * @deprecated The fingerprint is now calculated from the given key.
     */
    @Deprecated
    public byte[] sign(final String login,
                       final String fingerprint,
                       final KeyPair keyPair,
                       final byte[] data) {
        return sign(login, keyPair, data);
    }

    /**
     * Cryptographically signs an any data input.
     *
     * @param login Account/login name
     * @param keyPair public/private keypair
     * @param data data to be signed
     * @return signed value of data
     */
    public byte[] sign(final String login,
                       final KeyPair keyPair,
                       final byte[] data) {
        Objects.requireNonNull(login, "Login must be present");
        Objects.requireNonNull(keyPair, "Keypair must be present");
        Objects.requireNonNull(data, "Data must be present");

        try {
            signature.initSign(keyPair.getPrivate());
            signature.update(data);
            return signature.sign();
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
     * @param fingerprint key fingerprint (ignored)
     * @param keyPair public/private keypair
     * @param data data that was signed
     * @param signedData data to verify against signature
     * @return signed value of data
     *
     * @deprecated The fingerprint is now calculated from the given key.
     */
    @Deprecated
    public boolean verify(final String login,
                                 final String fingerprint,
                                 final KeyPair keyPair,
                                 final byte[] data,
                                 final byte[] signedData) {
        return verify(login, keyPair, data, signedData);
    }

    /**
     * Cryptographically signs an any data input.
     *
     * @param login Account/login name
     * @param keyPair public/private keypair
     * @param data data that was signed
     * @param signedData data to verify against signature
     * @return signed value of data
     */
    public boolean verify(final String login,
                          final KeyPair keyPair,
                          final byte[] data,
                          final byte[] signedData) {
        Objects.requireNonNull(login, "Login must be present");
        Objects.requireNonNull(keyPair, "Keypair must be present");
        Objects.requireNonNull(signedData, "Data must be present");

        try {
            signature.initVerify(keyPair.getPublic());
            signature.update(data);
            return signature.verify(signedData);
        } catch (final InvalidKeyException e) {
            throw new CryptoException("invalid key", e);
        } catch (final SignatureException e) {
            throw new CryptoException("invalid signature", e);
        }
    }

    /**
     * The current timestamp in UTC as a RFC 822 compliant string.
     * @return Date as RFC 822 compliant string
     */
    public String defaultSignDateAsString() {
        return DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneOffset.UTC));
    }

    /**
     * Verify a signed HTTP Authorization header.
     *
     * @param keyPair public/private keypair
     * @param authzHeader authorization header value
     * @param date Date as RFC 822 compliant string
     * @return True if the request is valid, false if not.
     * @throws CryptoException If unable to verify the request.
     */
    public boolean verifyAuthorizationHeader(final KeyPair keyPair,
                                             final String authzHeader,
                                             final String date) {
        Objects.requireNonNull(keyPair, "Keypair must be present");
        Objects.requireNonNull(authzHeader, "AuthzHeader must be present");
        Objects.requireNonNull(date, "Date must be present");

        String myDate = String.format(AUTHZ_SIGNING_STRING, date);

        try {
            signature.initVerify(keyPair.getPublic());

            final int startIndex = authzHeader.indexOf(AUTHZ_PATTERN);
            if (startIndex == -1) {
                throw new CryptoException(
                        String.format("invalid authorization header %s", authzHeader));
            }

            final String encodedSignedDate = authzHeader.substring(startIndex + AUTHZ_PATTERN.length(),
                    authzHeader.length() - 1);
            final byte[] signedDate = Base64.decode(encodedSignedDate.getBytes(StandardCharsets.UTF_8));

            signature.update(myDate.getBytes(StandardCharsets.UTF_8));
            return signature.verify(signedDate);

        } catch (final InvalidKeyException e) {
            throw new CryptoException("invalid key", e);
        } catch (final SignatureException e) {
            throw new CryptoException("invalid signature", e);
        }
    }

    /**
     * Return a string representation of the full algorithm.  For
     * example: "rsa-sha256"
     *
     * @return Algorithm name.
     */
    public String getHttpHeaderAlgorithm() {
        return httpHeaderAlgorithm;
    }

    /**
     * This method is visible for tests or benchmarks.
     *
     * @return instance of the signature cipher implementation
     */
    Signature getSignature() {
        return signature;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("Signer{");
        sb.append("signature=").append(signature);
        sb.append(",provider=").append(signature.getProvider().getName());
        sb.append(",httpHeaderAlgorithm=").append(httpHeaderAlgorithm);
        sb.append('}');
        return sb.toString();
    }

    /**
     * Builder class for {@link Signer}.
     *
     * The signing algorithm can be identified by a string (using the
     * same names as {@link java.security.PrivateKey#getAlgorithm}),
     * or by just passing in a {@link java.security.KeyPair}.  The
     * supported singing algorithms are RSA, DSA, and ECDSA.
     *
     * Signers can be further configured by specifying a string
     * representation of a hashing algorithms.  For example, {@code
     * SHA512} instead of {@code SHA256}.  The default is {@code
     * SHA256} in for all cases. The supported hash names are:
     *
     * <ul>
     * <li>RSA: {@code SHA1}, {@code SHA256}, {@code SHA512}</li>
     * <li>DSA: {@code SHA1}, {@code SHA256}</li>
     * <li>ECDSA: {@code SHA256}, {@code SHA384}, {@code SHA512}</li>
     * </ul>
     *
     * {@code providerCode} is designate and alternative provider to
     * the standard library. Currently the only algorithm that
     * supports a custom provider is {@code RSA} with {@code
     * native.jnagmp}.  This is the default.  See {@link
     * com.joyent.http.signature.crypto.NativeRSAWithSHA} for more
     * information.  All singing algorithms support {@code stdlib} to
     * use the standard library.
     */
    @SuppressWarnings("checkstyle:javadocvariable")
    public static class Builder {
        private final SigningAlgorithmHelper algHelper;
        private String hash;
        private String providerCode;

        /**
         * Instantiate a new Builder based on the algorithm of the
         * given keypair.
         *
         * @param keyPair The given KeyPair.
         */
        public Builder(final KeyPair keyPair) {
            this.algHelper = SigningAlgorithmHelper.create(keyPair);
            hash = algHelper.defaultHash();
            providerCode = algHelper.defaultProviderCode();
        }

        /**
         * Instantiate a new Builder based on the explicitly given
         * algorithm.
         *
         * @param algorithm {@link java.security.PrivateKey#getAlgorithm}
         */
        public Builder(final String algorithm) {
            this.algHelper = SigningAlgorithmHelper.create(algorithm);
            hash = algHelper.defaultHash();
            providerCode = algHelper.defaultProviderCode();
        }

        /**
         * Overrides the default hash type.
         *
         * @param hash New hash type
         * @return This {@code Builder} object
         */
        @SuppressWarnings("checkstyle:hiddenfield")
        public Builder hash(final String hash) {
            algHelper.checkSupportedHash(hash);
            this.hash = hash;
            return this;
        }

        /**
         * Overrides the default provider code.
         *
         * @param providerCode New provider code
         * @return This {@code Builder} object
         */
        @SuppressWarnings("checkstyle:hiddenfield")
        public Builder providerCode(final String providerCode) {
            algHelper.checkSupportedProviderCode(providerCode);
            this.providerCode = providerCode;
            return this;
        }

        /**
         * From the configured singing algorithm and hash, return a
         * string representation as used by the @see <a
         * href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature">Java
         * Cryptography Architecture Standard Algorithm Name
         * Documentation</a>.
         *
         * @param provider Provider used for signing.
         * @return The standard representation
         */
        private String javaStandardName(final Provider provider) {
            return hash + "with" + algHelper.providerPrefix(provider) + algHelper.getAlgorithm();
        }

        /**
         * From the configured signing algorithm and hash, return the
         * representation formatted for the HTTP Signature field.
         *
         * @return The header string
         */
        private String httpHeaderAlgorithm() {
            return algHelper.getAlgorithm().toLowerCase() + "-" + hash.toLowerCase();
        }

        /**
         * Returns a newly-created {@code Signer} based on the contents of the
         * {@code Builder}.
         *
         * @return The new {@code Builder}
         */
        public Signer build() {
            return new Signer(this);
        }

        /**
         * Helper class with per algorithm configuration.
         */
        private abstract static class SigningAlgorithmHelper {


            /**
             * Create a new {@code SigningAlgorithmHelper} based on
             * the given {@code KeyPair}.
             *
             * @param keyPair {@code} KeyPair to sign for
             * @return New {@code SigningAlgorithmHelper} instance.
             */
            public static SigningAlgorithmHelper create(final KeyPair keyPair) {
                return create(keyPair.getPrivate().getAlgorithm());
            }

            /**
             * Create a new {@code SigningAlgorithmHelper} based on
             * the given algorithm code.

             * @param algorithm {@see java.security.KeyPair#getAlgorithm}
             * @return New {@code SigningAlgorithmHelper} instance.
            */
            public static SigningAlgorithmHelper create(final String algorithm) {
                if (algorithm.equals("RSA")) {
                    return new RsaHelper();
                } else if (algorithm.equals("DSA")) {
                    return new DsaHelper();
                    // See NssBridgeKeyConverter on the two names
                } else if (algorithm.equals("ECDSA") || algorithm.equals("EC")) {
                    return new EcdsaHelper();
                } else {
                    throw new IllegalArgumentException("invalid signing algorithm: " + algorithm);
                }
            }

            /**
             * Return the string code for the instantiated algorithm helper.
             *
             * @return {@see java.security.KeyPair#getAlgorithm}
             */
            public abstract String getAlgorithm();

            /**
             * Get all of the hash algorithms supported by the
             * algorithm, in sorted order.
             *
             * @return The sorted hash algorihtm names.
             */
            public abstract String[] getSupportedHashes();

            /**
             * Get the default hash name for this signing algorithm.
             *
             * @return The default hash name.
             */
            public abstract String defaultHash();

            /**
             * Get all of the provider codes supported by the
             * algorithm, in sorted order.
             *
             * @return The sorted provider codes.
             */
            public abstract String[] getSupportedProviderCodes();

            /**
             * Get the default provider code for this signing algorithm.
             *
             * @return The default provider code
             */
            public abstract String defaultProviderCode();

            /**
             * Throws {@code IllegalArgumentException} if the given
             * {@code String} does not match a supported hash algorithm.
             *
             * @param hash Name to check.
             */
            public void checkSupportedHash(final String hash) {
                if (Arrays.binarySearch(getSupportedHashes(), hash) == -1) {
                    throw new IllegalArgumentException("invalid hash algorithm: " + hash);
                }
            }

            /**
             * Throws {@code IllegalArgumentException} if the given
             * {@code String} does not match a supported provider code.
             *
             * @param providerCode Name to check.
             */
            public void checkSupportedProviderCode(final String providerCode) {
                if (Arrays.binarySearch(getSupportedProviderCodes(), providerCode) == -1) {
                    throw new IllegalArgumentException("invalid providerCode algorithm: " + providerCode);
                }
            }

            /**
             * A {@code Provider} outside of the Java standard
             * library, might have a special "Algorithm Name".  @see
             * Signer.Builder#javaStandardName and @see #makeProvider
             *
             * @param provider The {@code Provider} from @see #makeProvider.
             * @return The "Algorithm Name" modification, or the empty string.
             */
            public String providerPrefix(final Provider provider) {
                return "";
            }

            /**
             * If a special {@link java.security.Provider} is
             * requested, construct and return it, otherwise return
             * {@code null} to use the Java standard library.
             *
             * @param providerCode The configured {@code Provider}
             * code.
             * @return The new {@link java.security.Provider}, or
             * {@code null} if using the standard library.
             */
            public Provider makeProvider(final String providerCode) {
                return null;
            }
        }

        /**
         * RSA implementation of {@code SigningAlgorithmHelper}.
         */
        @SuppressWarnings({"checkstyle:javadocmethod", "checkstyle:javadoctype"})
        private static class RsaHelper extends SigningAlgorithmHelper {
            private static final String[] SUPPORTED_HASHES = {"SHA1", "SHA256", "SHA512"};
            private static final String[] SUPPORTED_PROVIDER_CODES = {"native.jnagmp", "stdlib"};

            /**
             * OS names with native support in jnagmp.
             * Always keep values sorted because we binary search them.
             */
            private static final String[] SUPPORTED_NATIVE_OS =
                new String[] {"linux", "mac os x", "sunos"};

            /**
             * Architectures with native support in jnagmp.
             * Always keep values sorted because we binary search them.
             */
            private static final String[] SUPPORTED_NATIVE_ARCH =
                new String[] {"amd64", "x86_64"};

            /**
             * When true we are on a platform that supports native libgmp for modpow.
             */
            private static final boolean JNAGMP_SUPPORTED;

            static {
                final String os = System.getProperty("os.name").toLowerCase();
                final String arch = System.getProperty("os.arch").toLowerCase();

                JNAGMP_SUPPORTED = Arrays.binarySearch(SUPPORTED_NATIVE_OS, os) >= 0
                    && Arrays.binarySearch(SUPPORTED_NATIVE_ARCH, arch) >= 0;

                System.setProperty("native.jnagmp", Objects.toString(JNAGMP_SUPPORTED));
            }

            @Override
            public String getAlgorithm() {
                return "RSA";
            }

            @Override
            public String[] getSupportedHashes() {
                return SUPPORTED_HASHES;
            }

            @Override
            public String defaultHash() {
                return "SHA256";
            }

            @Override
            public String[] getSupportedProviderCodes() {
                return SUPPORTED_PROVIDER_CODES;
            }

            @Override
            public String defaultProviderCode() {
                return "native.jnagmp";
            }

            @Override
            public String providerPrefix(final Provider provider) {
                if (provider != null) {
                    return "Native";
                } else {
                    return "";
                }
            }

            @Override
            public Provider makeProvider(final String providerCode) {
                if (providerCode.equals("native.jnagmp") && JNAGMP_SUPPORTED) {
                    try {
                        return new NativeRSAProvider();
                        // if ANYTHING goes wrong, we default to the JVM implementation of the signing algo
                    } catch (Exception e) {
                        e.printStackTrace();
                        return null;
                    }
                } else {
                    return null;
                }
            }
        }

        /**
         * DSA implementation {@code SigningAlgorithmHelper}.
         */
        @SuppressWarnings({"checkstyle:javadocmethod", "checkstyle:javadoctype"})
        private static class DsaHelper extends SigningAlgorithmHelper {
            private static final String[] SUPPORTED_HASHES = {"SHA1", "SHA256"};
            private static final String[] SUPPORTED_PROVIDER_CODES = {"stdlib"};

            @Override
            public String getAlgorithm() {
                return "DSA";
            }
            @Override
            public String[] getSupportedHashes() {
                return SUPPORTED_HASHES;
            }

            @Override
            public String defaultHash() {
                return "SHA256";
            }

            @Override
            public String[] getSupportedProviderCodes() {
                return SUPPORTED_PROVIDER_CODES;
            }

            @Override
            public String defaultProviderCode() {
                return "stdlib";
            }
        }

        /**
         * ECDSA implementation {@code SigningAlgorithmHelper}.
         */
        @SuppressWarnings({"checkstyle:javadocmethod", "checkstyle:javadoctype"})
        private static class EcdsaHelper extends SigningAlgorithmHelper {
            private static final String[] SUPPORTED_HASHES = {"SHA256", "SHA384", "SHA512"};
            private static final String[] SUPPORTED_PROVIDER_CODES = {"stdlib"};

            @Override
            public String getAlgorithm() {
                return "ECDSA";
            }

            @Override
            public String[] getSupportedHashes() {
                return SUPPORTED_HASHES;
            }

            @Override
            public String defaultHash() {
                return "SHA256";
            }

            @Override
            public String[] getSupportedProviderCodes() {
                return SUPPORTED_PROVIDER_CODES;
            }

            @Override
            public String defaultProviderCode() {
                return "stdlib";
            }
        }
    }
}
