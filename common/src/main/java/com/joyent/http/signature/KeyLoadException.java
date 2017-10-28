/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

/**
 * Exception that can occur while loading a {@link java.security.KeyPair}.
 *
 * @since 4.0.4
 * @author <a href="https://github.com/tjcelaya">Tomas Celayac</a>
 */
public class KeyLoadException extends HttpSignatureException {

    private static final long serialVersionUID = 3842266217250311085L;

    /**
     * Creates a new exception with the specified message.
     * @param message Message to embed
     */
    public KeyLoadException(final String message) {
        super(message);
    }
}
