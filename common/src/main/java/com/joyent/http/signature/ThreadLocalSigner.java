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
     * Flag indicating the status of native code acceleration of cryptographic singing.
     */
    private final boolean useNativeCodeToSign;

    /**
     * Create a new thread-local instance of {@link Signer}.
     *
     * @param useNativeCodeToSign true to enable native code acceleration of cryptographic singing
     */
    public ThreadLocalSigner(final boolean useNativeCodeToSign) {
        this.useNativeCodeToSign = useNativeCodeToSign;
    }

    /**
     * Create a new thread-local instance of {@link Signer}.
     *
     */
    public ThreadLocalSigner() {
        this.useNativeCodeToSign = true;
    }

    @Override
    protected Signer initialValue() {
        threadsReferencing.add(Thread.currentThread());
        return new Signer(useNativeCodeToSign);
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
