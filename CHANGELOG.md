# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [2.0.0] - ?
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
