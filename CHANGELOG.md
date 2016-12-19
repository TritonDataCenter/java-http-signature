# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [3.0.0] - 2016-12-19
## Changed
 - Deprecated com.joyent.http.signature.google.httpclient.RequestHttpSigner.signURI.
   This method is now being provided directly in the Manta SDK.
 - Upgraded to jnagmp 2.0.0.
## Added
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
