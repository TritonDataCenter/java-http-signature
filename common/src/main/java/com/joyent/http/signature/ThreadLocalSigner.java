/*
 * Copyright (c) 2016-2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * Creates a thread-local copy of {@link Signer}. Cryptographic signature classes
 * are not thread safe. This class provides methods to get a singleton instance
 * per thread.
 *
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 */
public class ThreadLocalSigner extends ThreadLocal<Signer> {
    /**
     * Set of threads that have set ThreadLocal references.
     */
    private static Set<Thread> threadsReferencing =
            new CopyOnWriteArraySet<>();

    /**
     * {@code Signer.Builder} with configuration that will be used to
     * instantiate new {@code Signer}s on demand.
     */
    private Signer.Builder builder;

    /**
     * Create a new thread-local instance of {@link Signer} with the
     * same defaults as in version 3.x.
     *
     * @deprecated @see #ThreadLocalSigner(final boolean useNativeCodeToSign)
     *
     */
    @Deprecated
    public ThreadLocalSigner() {
        this(true);
    }

    /**
     * Create a new thread-local instance of {@link Signer} with the
     * same defaults as in version 3.0, but optionally toggling {@code
     * native.jnagmp} acceleration.
     *
     * @param useNativeCodeToSign true to enable native code acceleration of cryptographic singing
     *
     * @deprecated Passing a {@link Signer.Builder} is now the
     * preferred constructor.  The use of these constructors tends to
     * encourage error prone use with multiple {@code
     * ThreadLocalSigner} instances unintentionally operating on the
     * same keys.
     */
    @Deprecated
    @SuppressWarnings("checkstyle:avoidinlineconditionals")
    public ThreadLocalSigner(final boolean useNativeCodeToSign) {
        builder = new Signer.Builder("RSA").providerCode(useNativeCodeToSign ? "native.jnagmp" : "stdlib");
    }

    /**
     * Create a new thread-local instance of {@link Signer} with each
     * {@link Signer} configured by the given {@link Signer.Builder}.
     *
     * @param builder {@code Signer.Builder} with configuration that
     * will be used to instantiate new {@code Signer}s on demand.
    */
    public ThreadLocalSigner(final Signer.Builder builder) {
        this.builder = builder;
    }

    @Override
    protected Signer initialValue() {
        threadsReferencing.add(Thread.currentThread());
        return builder.build();
    }

    @Override
    public void remove() {
        super.remove();
        threadsReferencing.remove(Thread.currentThread());
    }

    @Override
    public void set(final Signer value) {
        super.set(value);

        if (value == null) {
            threadsReferencing.remove(Thread.currentThread());
        }
    }

    /**
     * Removes all thread-local values.
     */
    public void clearAll() {
        /* We peel back the layers of ThreadLocal's internal implementation in order to
         * provide consumers of the library a method which they can use to mitigate memory
         * leaks.
         */
        try {
            Method getMap = ThreadLocal.class.getDeclaredMethod("getMap", Thread.class);
            getMap.setAccessible(true);
            Class<?> threadLocalMapClass = Class.forName("java.lang.ThreadLocal$ThreadLocalMap");
            Method remove = threadLocalMapClass.getDeclaredMethod("remove", ThreadLocal.class);
            remove.setAccessible(true);

            for (Thread t : threadsReferencing) {
                Object map = getMap.invoke(this, t);

                if (map != null) {
                    remove.invoke(map, this);
                }
            }
        } catch (ClassNotFoundException | NoSuchMethodException
                 | IllegalAccessException | InvocationTargetException
                 | NullPointerException e) {
            throw new ThreadLocalClearException(e);
        }
    }
}
