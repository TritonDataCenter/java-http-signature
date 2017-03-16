package com.joyent.http.signature.apache.httpclient;

import com.joyent.http.signature.ThreadLocalSigner;
import org.apache.http.*;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.security.KeyPair;
import java.util.*;

import static org.testng.Assert.assertEquals;

/**
 * Integration test for testing the Apache HTTP Client with HTTP Signature
 * authentication. This test needs to be run manually at this time.
 */
@SuppressWarnings("deprecation")
public class HttpSignatureAuthIT {
    public static final String SDC_KEY_ID_ENV_KEY = "SDC_KEY_ID";
    private static final String SDC_URL_ENV_KEY = "SDC_URL";
    private static final String SDC_ACCOUNT_ENV_KEY = "SDC_ACCOUNT";
    private static final String SDC_KEY_PATH_ENV_KEY = "SDC_KEY_PATH";

//    @Test
    public void canAuthenticate() throws IOException {
        final KeyPair keyPair = createKeyPair();

        final String user = System.getenv(SDC_ACCOUNT_ENV_KEY);
        Objects.requireNonNull(user, SDC_ACCOUNT_ENV_KEY + " must be set");

        final String keyId = System.getenv(SDC_KEY_ID_ENV_KEY);
        Objects.requireNonNull(keyId, SDC_KEY_ID_ENV_KEY + " must be set");

        final Credentials credentials = new UsernamePasswordCredentials(
                user, keyId);
        HttpSignatureConfigurator configurator = new HttpSignatureConfigurator(keyPair,
                credentials, true);

        try (CloseableHttpClient conn = createConnection(configurator)) {
            String baseUrl = System.getenv(SDC_URL_ENV_KEY);
            Objects.requireNonNull(baseUrl, SDC_URL_ENV_KEY + " must be present");

            URI uri = URI.create(String.format("%s/%s/machines",
                    baseUrl, user));

            HttpHead head = new HttpHead(uri);
            HttpClientContext context = new HttpClientContext();

//            AuthCache authCache = new BasicAuthCache();
//            context.setAuthCache(authCache);
//            AuthState authState = new AuthState();
//            authState.update(configurator.getAuthScheme(), credentials);
//
//            context.setAttribute(HttpClientContext.TARGET_AUTH_STATE,
//                    authState);
//            context.getTargetAuthState().setState(AuthProtocolState.UNCHALLENGED);
            HttpResponse response = conn.execute(head, context);

            assertEquals(response.getStatusLine().getStatusCode(),
                         HttpStatus.SC_OK);
        }
    }

    private CloseableHttpClient createConnection(final HttpSignatureConfigurator configurator) {
        final PoolingHttpClientConnectionManager connectionManager =
                new PoolingHttpClientConnectionManager();

        final RequestConfig requestConfig = RequestConfig.custom()
                .setAuthenticationEnabled(true)
                .setContentCompressionEnabled(true)
                .build();

        final Collection<? extends Header> headers = Arrays.asList(
                new BasicHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType())
        );

        final HttpClientBuilder httpClientBuilder = HttpClients.custom()
                .setDefaultHeaders(Collections.unmodifiableCollection(headers))
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(requestConfig);

        configurator.configure(httpClientBuilder);

        final HttpHost proxyHost = findProxyServer();

        if (proxyHost != null) {
            httpClientBuilder.setProxy(proxyHost);
        }

        return httpClientBuilder.build();
    }

    /**
     * Creates a {@link KeyPair} object based on the factory's configuration.
     * @return an encryption key pair
     */
    private KeyPair createKeyPair() {
        final KeyPair keyPair;
        final String keyPath = System.getenv(SDC_KEY_PATH_ENV_KEY);
        Objects.requireNonNull(keyPath, SDC_KEY_PATH_ENV_KEY + " must be set");
        final ThreadLocalSigner signer = new ThreadLocalSigner();

        try {
            keyPair = signer.get().getKeyPair(new File(keyPath).toPath());
        } catch (IOException e) {
            String msg = String.format("Unable to read key files from path: %s",
                    keyPath);
            throw new RuntimeException(msg, e);
        }

        return keyPair;
    }

    /**
     * Finds the host of the proxy server that was configured as part of the
     * JVM settings.
     *
     * @return proxy server as {@link HttpHost}, if no proxy then null
     */
    private HttpHost findProxyServer() {
        final ProxySelector proxySelector = ProxySelector.getDefault();
        final String rootURI = System.getenv(SDC_URL_ENV_KEY);
        Objects.requireNonNull(rootURI, "SDC_URL must be set");
        List<Proxy> proxies = proxySelector.select(URI.create(rootURI));

        if (!proxies.isEmpty()) {
            /* The Apache HTTP Client doesn't understand the concept of multiple
             * proxies, so we use only the first one returned. */
            final Proxy proxy = proxies.get(0);

            switch (proxy.type()) {
                case DIRECT:
                    return null;
                case SOCKS:
                    throw new RuntimeException("SOCKS proxies are unsupported");
                default:
                    // do nothing and fall through
            }

            if (proxy.address() instanceof InetSocketAddress) {
                InetSocketAddress sa = (InetSocketAddress) proxy.address();

                return new HttpHost(sa.getHostName(), sa.getPort());
            } else {
                String msg = String.format(
                        "Expecting proxy to be instance of InetSocketAddress. "
                                + " Actually: %s", proxy.address());
                throw new RuntimeException(msg);
            }
        } else {
            return null;
        }
    }
}
