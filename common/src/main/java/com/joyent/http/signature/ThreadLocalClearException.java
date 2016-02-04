package com.joyent.http.signature;

/**
 * Exception thrown when we have a problem clearing thread local variables.
 *
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 */
public class ThreadLocalClearException extends RuntimeException {
    /**
     * Constructs a new runtime exception with the specified cause and a
     * detail message of <tt>(cause==null ? null : cause.toString())</tt>
     * (which typically contains the class and detail message of
     * <tt>cause</tt>).  This constructor is useful for runtime exceptions
     * that are little more than wrappers for other throwables.
     *
     * @param cause the cause (which is saved for later retrieval by the
     *              {@link #getCause()} method).  (A <tt>null</tt> value is
     *              permitted, and indicates that the cause is nonexistent or
     *              unknown.)
     */
    public ThreadLocalClearException(final Throwable cause) {
        super(cause);
    }
}
