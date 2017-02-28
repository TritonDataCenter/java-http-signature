/*
 * Copyright (c) 2015-2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/**
 * Package containing utility classes for using HTTP Signature with the
 * Apache HTTP Client.
 *
 * There are two primary implementations an {@link org.apache.http.auth.AuthScheme}
 * implementation implemented as {@link com.joyent.http.signature.apache.httpclient.HttpSignatureAuthScheme} and
 * a {@link org.apache.http.HttpRequestInterceptor} implementation implemented
 * as {@link com.joyent.http.signature.apache.httpclient.HttpSignatureRequestInterceptor}.
 * Both classes are valid ways of implementing HTTP Signatures with the Apache
 * Commons HTTP Client. Depending on your application one implementation may
 * be better than another.
 *
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 */
package com.joyent.http.signature.apache.httpclient;
