package com.joyent.http.signature;

/**
 * General exception that all other exceptions inherit from in this project.
 *
 * @author <a href="https://github.com/dekobon">Elijah Zupancic</a>
 * @since 1.0.0
 */
public class HttpSignatureException  extends RuntimeException {
    public HttpSignatureException() {
    }

    public HttpSignatureException(String message) {
        super(message);
    }

    public HttpSignatureException(String message, Throwable cause) {
        super(message, cause);
    }

    public HttpSignatureException(Throwable cause) {
        super(cause);
    }

    public HttpSignatureException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
