# Java HTTP Signature Utilities

[java-http-signature](https://github.com/joyent/java-http-signature) is a 
community maintained set of utilities for making HTTP Signature requests against
the [Joyent Public Cloud](http://www.joyent.com).

This project is a fork of the code that once existed as part of the 
[Java Manta SDK](http://joyent.github.com/java-manta). Currently, this project
interacts directly with BouncyCastle to create HTTP Signatures. In the future,
we may use a project like [httpsig-java](https://github.com/adamcin/httpsig-java)
or [http-signatures-java](https://github.com/tomitribe/http-signatures-java) to
do the signing.

## Installation

### Requirements
* [Java 1.7](http://www.oracle.com/technetwork/java/javase/downloads/index.html) or higher.
* [Maven](https://maven.apache.org/)

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

### From Source
If you prefer to build from source, you'll also need
[Maven](https://maven.apache.org/), and then invoke:

``` bash
# mvn package
```

## Usage

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
``
