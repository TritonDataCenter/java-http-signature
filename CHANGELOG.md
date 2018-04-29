# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [4.0.8]

### Fixed
- [NullPointerException when key file is not a valid private key](https://github.com/joyent/java-http-signature/issues/50)

## [4.0.7] - 2018-04-02

### Fixed
 - [jaxrs-client-signature integration tests fail to work in Java 9](https://github.com/joyent/java-http-signature/issues/48)
### Changed
 - Upgraded dependency versions.

## [4.0.6] - 2017-12-18

### Fixed
 - [Removed reflective mofification of PKCS#11 Security Provider's algorithms map](https://github.com/joyent/java-http-signature/issues/45) which was incorrectly serializing ECDSA keys.

## [4.0.5] - 2017-10-20

### Fixed
 - [Removed use of javax.xml.bind.DatatypeConverter](https://github.com/joyent/java-http-signature/issues/41)
 - Resolved compiler warnings. 

## [4.0.4] - 2017-10-06

### Changed
 - Upgraded all dependencies to the latest version.

## [4.0.3] - 2017-04-04

### Added
 - The key fingerprint is now internally calculated instead of using a
   user supplied String.
 - Utility methods for calculating MD5 fingerprints, calculating
   SHA256 fingerprints, and verifying OpenSSH's string format have
   been added.
 - It is now possible to load a `KeyPair` from a `Path` or `File` in
   combination with a passphrase.

### Changed
 - Methods that took an explicit fingerprint `String` now ignore it in
   favor of the internally calculated one.  These methods have been
   deprecated and will be removed in a future version.

## [4.0.2] - 2017-03-23

### Changed
 - Bouncy Castle dependency was upgraded.
 - An unused dependency on Apache httpclient has been removed from the
  `common` module.
 
## [4.0.1] - 2017-03-20

### Added
 - HTTP signature caching with Apache HTTP Client module - signatures
   with the same date time value are now cached and signature 
   generation is skipped. This is useful for high-traffic connections
   to Manta.
 - Added support for libnss to do ECDSA signing via the PKCS11 interface.

## [4.0.0] - 2017-03-15

### Added
 - DSA and ECDSA keys (and signing) are now supported.  No changes are
   needed at this time if only RSA keys are used. See below for
   related API changes and deprecations.
 - Multiple hash algorithms (besides SHA256) are now supported.
   Because signing is almost always more expensive than hashing,
   changing from the default hashing algorithm is unlikely to yield a
   significant performance benefit.
 - A new `microbench` module contains micro-benchmarks to aid in the
   development of this library.  They are not a stable public
   contract.

### Changed
 - The minimum Java version is now 1.8.
 - To support multiple key types, a builder pattern is now the
   preferred way to instantiate `Signer` and `ThreadLocalSigner`.  See
   `Signer.Builder` for more details.  Given a key, the builder can
   select the appropriate signing algorithm.  The old constructors are
   now deprecated and will be removed in a future release.
 - Several public fields and methods of `Signer` that exposed internal
   details have been removed.  That is the breaking change of this
   release.
 - Since a `Signer` now needs a `KeyPair` to be instantiated, the
   various "get me a key" methods are moved to `KeyPairLoader`.  The
   old methods are now deprecated and will be removed in a future
   release.
 - Previously it was easy to end up with multiple ThreadLocalSigner
   instances.  This was mostly harmless (except for resources cleanup)
   when everything was hard coded to be `SHA256withRSA`, but quickly
   leads to errors when the signers have different configuration.  It
   is now best to create a single `ThreadLocalSigner` per key (ie
   usually just one) and pass that downstream.  Several classes in
   `apache-http-client` and `google-http-client` have changed to
   encourage this.  Methods that implicitly created an unconfigured
   `ThreadLocalSigner` are now deprecated and will be removed in a
   future release.

## [3.0.2] - 2017-03-03
### Added
 - We now use JCE specified message digests for calculating checksums.
   This allows for plugging native checksum algorithms.
 - We now append total signing time as an HTTP header. 
### Changed
 - Added MPLv2 headers to all of the source files.
 - Upgraded checkstyle version and added header check.

## [3.0.1] - 2016-12-29
### Changed
 - Used additional methods available from jnagmp to accelerate
   signature generation.

## [3.0.0] - 2016-12-19
### Changed
 - Deprecated com.joyent.http.signature.google.httpclient.RequestHttpSigner.signURI.
   This method is now being provided directly in the Manta SDK.
 - Upgraded to jnagmp 2.0.0.
### Added
 - Added HttpSignatureRequestInterceptor as an addition method to perform authentication with Apache HTTP Client. 

## [2.2.2] - 2016-10-25
### Fixed
 - [Fixed locales aren't hardcoded to English](https://github.com/joyent/java-http-signature/issues/13) 

### Changed
 - Upgraded Bouncy Castle libraries.
 - Upgraded Slf4j.
 - Upgraded Logback.
 - Upgraded Arquillian Glassfish Embedded.
 - Upgraded Jersey client.
 - Upgraded Payara Embedded Web.
 - Upgraded Arquillian TestNG container. 
 
## [2.2.1] - 2016-10-10
### Changed
 - Upgraded Apache HTTP Client.
 - Upgraded Google HTTP Client.

## [2.2.0] - 2016-04-19
### Changed
 - Changed license from MIT to the MPL v2.
 - Fixed #12 - Removed request id generation from Apache HTTP client helper 
   because it best belongs in the consumer of the library.
 - Fixed #12 - Removed request id generation from Google HTTP client helper
   because it best belongs in the consumer of the library.

## [2.1.0] - 2016-04-13
### Changed
 - Fixed #11 - Apache HTTP Client helper library will loop infinitely when 
   authentication fails.
### Added 
 - Added helper class HtpSignatureConfigurator that makes configuring 
   HttpClientBuilder instances easier.

## [2.0.4] - 2016-04-01
### Changed
 - Updated Apache HTTP Client libraries, so they don't always rechallenge.

## [2.0.3] - 2016-04-01
### Changed
 - Fixed Apache HTTP Client libraries, so that they work as expected.

## [2.0.2] - 2016-03-07
### Changed
 - Added OS detection of Illumos/SmartOS/Solaris so that the library can
   actually load the native jnagmp library in that environment.

## [2.0.1] - 2016-03-06
### Changed
 - Added better support for dealing with exceptions thrown when clearing
   threadlocals with `ThreadLocalSigner`. Added relevant exception class:
   `ThreadLocalClearException`.
 - Upgraded jnagmp library to 1.1.0 so that it supports the JVM on 
   Illumos/SmartOS/Solaris.

## [2.0.0] - 2016-01-07
### Changed
 - Renamed HttpSigner to Signer and changed it from a static utility class
   to an instance class.
 - Wrapped all Signer instances in ThreadLocal<> because the underlying
   field Signature is not compatible in any way with multi-threading.
 - Removed system properties configuration of native extentions and moved
   to an explicit constructor model.

## [1.1.0] - 2015-12-10
### Added
 - Added support for native RSA SHA256 calculation in order to improve HTTP
   signing performance.

### Changed
 - Upgraded Bouncy Castle dependency.
 - Upgraded Google HTTP Client dependency.

## [1.0.3] - 2015-12-10
### Changed
 - Removed inaccurate restriction on HTTP method for signing URLs.

## [1.0.2] - 2015-11-25
### Added
 - jaxrs-client module module added.

## [1.0.1] - 2015-11-23
### Added
 - Added support for signing arbitrary byte arrays.

## [1.0.0] - 2015-11-10
### Added
- Forked HTTP signature from the Java Manta project.
- Created three artifacts - common, google-http-client and apache-http-client
