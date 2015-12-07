/**
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */
package com.joyent.http.signature.jaxrs.client.testapp;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import java.util.HashSet;
import java.util.Set;


/**
 * Test application enumerating the resource classes to be included.
 *
 * @author <a href="https://github.com/phillipross">Phillip Ross</a>
 */
@ApplicationPath("api-endpoint")
public class TestApplication extends Application {


    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> classes = new HashSet<>();
        classes.add(TestResource.class);
        return classes;
    }


}
