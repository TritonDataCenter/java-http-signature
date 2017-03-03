package com.joyent.http.signature.apache.httpclient;

import com.joyent.http.signature.Signer;
import com.joyent.http.signature.ThreadLocalSigner;
import org.apache.http.Header;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class HttpSignatureRequestInterceptorTest {
    private static final String testKeyFingerprint = "04:92:7b:23:bc:08:4f:d7:3b:5a:38:9e:4a:17:2e:df";
    private KeyPair testKeyPair;
    private boolean useNativeCodeToSign;
    private ThreadLocalSigner signer;

    private HttpSignatureAuthScheme authScheme;

    private Credentials credentials = new UsernamePasswordCredentials(
            "username", testKeyFingerprint);
    private HttpSignatureRequestInterceptor interceptor;

    @Parameters({"useNativeCodeToSign"})
    @BeforeClass
    public void beforeClass(@Optional Boolean useNativeCodeToSign) throws IOException, NoSuchAlgorithmException {
        if (useNativeCodeToSign == null) {
            this.useNativeCodeToSign = true;
        } else {
            this.useNativeCodeToSign = useNativeCodeToSign;
        }

        this.signer = new ThreadLocalSigner(this.useNativeCodeToSign);
        // Removes any existing instances - so that we can reset state
        this.signer.remove();
        this.testKeyPair = testKeyPair(signer.get());

        this.authScheme = new HttpSignatureAuthScheme(testKeyPair, this.useNativeCodeToSign);
        this.interceptor = new HttpSignatureRequestInterceptor(authScheme, credentials,
                this.useNativeCodeToSign);
    }

    @Test
    public void signBenchmark() throws IOException, HttpException {
        Header[] headers = new Header[] {
                new BasicHeader("Content-Type", "application/json; type=directory"),
                new BasicHeader("x-request-id", "bb3ca512-c637-43c8-926b-2990caf64aee"),
                new BasicHeader("accept-version", "~1.0"),
                new BasicHeader("Accept", "application/json, */*"),
                new BasicHeader("Content-Length", "0"),
                new BasicHeader("Host", "us-east.manta.joyent.com:443"),
                new BasicHeader("Connection", "Keep-Alive"),
                new BasicHeader("User-Agent", "Java-Manta-SDK/3.0.0-SNAPSHOT (Java/1.8.0_76/Oracle Corporation)"),
                new BasicHeader("Accept-Encoding", "gzip,deflate"),
        };
        HttpRequest request = new HttpPut("https://us-east.manta.joyent.com:443");
        request.setHeaders(headers);

        HttpContext context = new BasicHttpContext();

        for (int i = 0; i < 10000; i++) {
            interceptor.process(request, context);
            String signTime = request.getFirstHeader("x-http-signing-time-ns").getValue();
            System.out.printf("Time to sign: %s\n", signTime);
        }
    }

    /**
     * @return a static key pair used for testing utility methods
     */
    private KeyPair testKeyPair(final Signer signer) throws IOException {
        final ClassLoader loader = HttpSignatureRequestInterceptor.class.getClassLoader();

        // Try to get keypair from class path first
        try (InputStream is = loader.getResourceAsStream("id_rsa")) {
            KeyPair classPathPair = signer.getKeyPair(is, null);
            if (classPathPair != null) {
                return classPathPair;
            }
        }

        // We couldn't get the key pair from the class path, so let's try
        // a directory relative to the project root.
        Path keyPath = new File("./src/test/resources/id_rsa").toPath();
        return signer.getKeyPair(keyPath);
    }
}
