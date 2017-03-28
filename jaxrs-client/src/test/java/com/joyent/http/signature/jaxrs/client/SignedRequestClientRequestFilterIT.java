/**
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */
package com.joyent.http.signature.jaxrs.client;

import com.joyent.http.signature.SignerTestUtil;
import com.joyent.http.signature.jaxrs.client.testapp.TestApplication;
import com.joyent.http.signature.jaxrs.client.testapp.TestResource;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.json.JsonObject;
import javax.json.JsonValue;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;


/**
 * Tests the functionality of the SignedRequestClientRequestFilter with a Jersey client.
 *
 * @author <a href="https://github.com/phillipross">Phillip Ross</a>
 */
public class SignedRequestClientRequestFilterIT extends Arquillian {

    private static final Logger logger = LoggerFactory.getLogger(SignedRequestClientRequestFilterIT.class);

    private static final String TEST_LOGIN_NAME = "testy";

    private static final String TEST_KEY_FINGERPRINT = SignerTestUtil.testKeyMd5Fingerprint("rsa_2048");

    /**
     * URL path element corresponding to the test JAX-RS application.  This value must match
     * the application path defined by the application.
     */
    private static final String TEST_JAXRS_APPLICATION_ENDPOINT = "api-endpoint";

    /**
     * URL path element corresponding to the test JAX-RS resource.  This value must match
     * the resource path defined in the test resource.
     */
    private static final String TEST_RESOURCE_PATH = "testResource";

    /**
     * URL path element corresponding to the test method within the JAX-RS resource.
     * This value must match the method path defined in the method of the test resource.
     */
    private static final String TEST_RESOURCE_METHOD_PATH = "returnHeaders";

    /**
     * Arquillian will populate this with the corresponding base URL for the application as is
     * deployed within the container.  The test methods can then use this base URL to build
     * HTTP requests from.
     */
    @ArquillianResource
    URL endpointBaseUrl;


    /**
     * Create the deployment.
     *
     * This will archive the JAX-RS application and resource used for testing into a war file
     * which will then be deployed into the embedded container by arquillian.  The testable
     * attribute for the annotation denotes that this test class will run as a client OUTSIDE
     * of the deployed application.
     *
     * @return {@link org.jboss.shrinkwrap.api.spec.WebArchive} containing the test application
     */
    @Deployment(testable = false)
    public static WebArchive createDeployment() {
        return ShrinkWrap.create(WebArchive.class)
                .addClasses(
                        TestApplication.class,
                        TestResource.class
                );
    }


    /**
     * Test and verify that the Authorization and Date headers are set by the filter.
     *
     * This simply tests that the headers are set by the filter, received by a JAX-RS resource, wrapped in a
     * specially formatted JSON object, and returned to the client in a GET request.  The signature is
     * not actually validated.  Only that the headers are received and that the authorization header contains
     * the correct components (keyId, algorithm, and signature)
     *
     * @throws URISyntaxException if the endpoint URI is malformed.
     * @throws IOException if unable to read test key
     */
    @Test
    public void testSignedRequestWithFilter() throws URISyntaxException, IOException {
        Assert.assertNotNull(endpointBaseUrl);

        final SignedRequestClientRequestFilter signedRequestClientRequestFilter = new SignedRequestClientRequestFilter(
                TEST_LOGIN_NAME,
                TEST_KEY_FINGERPRINT,
                SignerTestUtil.testKeyPair("rsa_2048")
        );

         Invocation.Builder builder = ClientBuilder.newClient()
                .register(signedRequestClientRequestFilter)
                .target(endpointBaseUrl.toURI())
                .path(TEST_JAXRS_APPLICATION_ENDPOINT)
                .path(TEST_RESOURCE_PATH)
                .path(TEST_RESOURCE_METHOD_PATH)
                .request(MediaType.APPLICATION_JSON_TYPE);

        final Response response;

        try {
            response = builder.get();
        } catch (RuntimeException e) {
            logger.error("Error accessing endpoint: {}", endpointBaseUrl, e);
            throw e;
        }

        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getStatus());
        Assert.assertEquals(response.getStatus(), 200);
        logger.debug("response status code: {}", response.getStatus());
        Assert.assertNotNull(response.getMediaType());
        Assert.assertEquals(response.getMediaType(), MediaType.APPLICATION_JSON_TYPE);
        logger.debug("response media type: {}", response.getMediaType());

        JsonObject jsonObject = response.readEntity(JsonObject.class);
        Assert.assertNotNull(jsonObject);
        logger.debug("response entity json object content: {}", jsonObject);

        Assert.assertNotNull(jsonObject.get(SignedRequestClientRequestFilter.DATE_HEADER_NAME.toLowerCase()));
        Assert.assertEquals(
                jsonObject.get(SignedRequestClientRequestFilter.DATE_HEADER_NAME.toLowerCase())
                        .getValueType(),
                JsonValue.ValueType.ARRAY
        );
        Assert.assertNotNull(jsonObject.get(SignedRequestClientRequestFilter.AUTHORIZATION_HEADER_NAME.toLowerCase()));
        Assert.assertEquals(
                jsonObject.get(SignedRequestClientRequestFilter.AUTHORIZATION_HEADER_NAME.toLowerCase())
                        .getValueType(),
                JsonValue.ValueType.ARRAY
        );

        String authorizationString = jsonObject.getJsonArray(
                SignedRequestClientRequestFilter.AUTHORIZATION_HEADER_NAME.toLowerCase()
        ).getString(0);

        Assert.assertTrue(
                authorizationString.startsWith("Signature keyId=")
                        && authorizationString.contains("algorithm=\"rsa-sha256\"")
                        && authorizationString.contains("signature=")
        );
    }


}
