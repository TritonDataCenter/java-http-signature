# Java HTTP Signature Utilities

[java-http-signature](https://github.com/joyent/java-http-signature) is a 
community maintained set of utilities for making HTTP Signature requests against
the [Joyent Public Cloud](http://www.joyent.com).

This project is a fork of the code that once existed as part of the 
[Java Manta SDK](http://joyent.github.com/java-manta). Currently, this project
interacts directly with [Bouncy Castle](https://www.bouncycastle.org/) to create 
HTTP Signatures. In the future, we may use a project like 
[httpsig-java](https://github.com/adamcin/httpsig-java)
or [http-signatures-java](https://github.com/tomitribe/http-signatures-java) to
do the signing.

## Installation

### Requirements
* [Java 1.7](http://www.oracle.com/technetwork/java/javase/downloads/index.html) or higher.
* [Maven 3.3](https://maven.apache.org/)

## Using Maven
Add the latest dependency to your Maven `pom.xml`.

For Apache HTTP Client AuthScheme support: 
```xml
<dependency>
    <groupId>com.joyent.http-signature</groupId>
    <artifactId>apache-http-client-signature</artifactId>
    <version>LATEST</version>
</dependency>
```

For Google HTTP Client support:
```xml
<dependency>
    <groupId>com.joyent.http-signature</groupId>
    <artifactId>google-http-client-signature</artifactId>
    <version>LATEST</version>
</dependency>
```

For JAX-RS Client support:
```xml
<dependency>
    <groupId>com.joyent.http-signature</groupId>
    <artifactId>jaxrs-client-signature</artifactId>
    <version>LATEST</version>
</dependency>
```

### From Source
If you prefer to build from source, you'll also need
[Maven](https://maven.apache.org/), and then invoke:

``` bash
# mvn package
```

## Usage

### Thread Safety Warning

The Java Cryptographic Extensions Signature class is not thread safe,
but it is entirely likely that you will want to use multiple threads
to generate HTTP signatures. You can solve this problem by using the
included `ThreadLocalSigner` class. However, this class has the limitation
of storing one Signer class per invoking thread. Be very careful that
you properly shut down your threads and do not accidentally create a
memory leak. To nuke all of the thread references, you can call the 
`clearAll()` method on `ThreadLocalSigner`.

The `ThreadLocal` approach is used by default in the `jaxrs-client`,
the `google-http-client` and the `apache-http-client` modules.

### Google HTTP Client Integration

You will need to create a HttpSigner object and then use that object as part
of an Interceptor to sign the request object. For example:

```java
public static HttpRequestFactory buildRequestFactory() {
    String keyPath = "/path/to/my/rsa/key";
    String login = "account_name";
    String fingerprint = "b2:b2:b2:b2:b2:b2:b2:b2:f7:f7:f7:f7:f7:f7:f7:f7";
    HttpSignerUtils.getKeyPair(new File(keyPath).toPath()); 
    HttpSigner signer = new HttpSigner(keyPair, login, fingerprint);
    
    HttpExecuteInterceptor signingInterceptor = new HttpExecuteInterceptor() {
        @Override
        public void intercept(final HttpRequest request) throws IOException {
            httpSigner.signRequest(request);
        }
    };
    
    HttpRequestInitializer initializer = new HttpRequestInitializer() {
        @Override
        public void initialize(final HttpRequest request) throws IOException {
            request.setInterceptor(signingInterceptor);
            request.setParser(new JsonObjectParser(JSON_FACTORY));
        }
    };
    
    HttpTransport transport = new NetHttpTransport();
    
    return transport.createRequestFactory(initializer);
}
```

### JAX-RS Client Integration

To use the JAX-RS Client integration, instantiate a `SignedRequestClientRequestFilter` with
the proper credentials, then register this instance with the JAX-RS Client.
For example:

```java
    String keyPath = "/path/to/my/rsa/key";
    String login = "account_name";
    String fingerprint = "b2:b2:b2:b2:b2:b2:b2:b2:f7:f7:f7:f7:f7:f7:f7:f7";
    final SignedRequestClientRequestFilter signedRequestClientRequestFilter = new SignedRequestClientRequestFilter(
        login,
        fingerprint,
        keyPath
    );

    Response response = ClientBuilder.newClient()
        .register(signedRequestClientRequestFilter)
        .target(endpointBaseUrl.toURI())
        .request(MediaType.APPLICATION_JSON_TYPE)
        .get();
```                

## Contributions

Contributions welcome! Please read the [CONTRIBUTING.md](CONTRIBUTING.md) document for details
on getting started.

### Releasing

Please refer to the [release documentation](RELEASING.md).

### Bugs

See <https://github.com/joyent/java-http-signature/issues>.

## License
Triton Java is licensed under the MPLv2. Please see the `LICENSE.txt` file for more details.
