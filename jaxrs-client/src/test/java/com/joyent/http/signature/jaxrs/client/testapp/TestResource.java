package com.joyent.http.signature.jaxrs.client.testapp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.RequestScoped;
import javax.inject.Named;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;


/**
 * JAX-RS resource class for testing REST requests.
 *
 * @author <a href="https://github.com/phillipross">Phillip Ross</a>
 */
@Path("/testResource")
@Named
@RequestScoped
public class TestResource {

    private static final Logger logger = LoggerFactory.getLogger(TestResource.class);


    @GET
    @Path("/returnHeaders")
    @Produces("application/json")
    public Response test(@Context HttpHeaders headers) {
        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder();
        logger.debug("invoked getIt() method.");
        for (String key : headers.getRequestHeaders().keySet()) {
            logger.debug("key: {}", key);
            JsonArrayBuilder jsonArrayBuilder = Json.createArrayBuilder();
            for (String value : headers.getRequestHeader(key)) {
                logger.debug("   value: {}", value);
                jsonArrayBuilder.add(value);
            }
            jsonObjectBuilder.add(key, jsonArrayBuilder);
        }
        JsonObject jsonObject = jsonObjectBuilder.build();
        return Response.ok(jsonObject).build();
    }


}
