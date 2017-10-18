/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature.crypto;

import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 * There is an unfortunate naming discrepancy between BouncyCastle and
 * other security providers over the name of ECDSA.  BouncyCastle uses
 * the string "ECDSA", while several standard library providers use
 * the string "EC".  This means that regardless of the configured
 * provider preferences, JcaPEMKeyConverter will always end up using
 * the "BC" (BouncyCastle) provider for ECDSA.  This is generally
 * benign because the same algorithms are implimented, and
 * BouncyCastle is often faster.  However, it does prevent calling out
 * to NSS via the PKCS#11 provider.  In the case of ECDSA,
 * microbenchmarks demonstrate that NSS is significantly faster than
 * BouncyCastle.
 *
 * @see <a href="http://docs.oracle.com/javase/8/docs/technotes/guides/security/p11guide.html">PKCS#11 Reference Guide</a>
 * @see <a href="https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS">Network Security Services</a>
 */
@Deprecated
public class NssBridgeKeyConverter extends JcaPEMKeyConverter {
}
