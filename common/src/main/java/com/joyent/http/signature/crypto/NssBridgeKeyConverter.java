/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature.crypto;

import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Provider;
import java.security.Security;

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
public class NssBridgeKeyConverter extends JcaPEMKeyConverter {

    {
        Provider[] providers = Security.getProviders();
        try {
            if (providers == null || providers.length == 0) {
                /* A lack of any security providers should be
                 * an "impossible" condition.  But if it occurs we print
                 * to stderr instead of throwing in a static
                 * initializer.
                 */
                System.err.println("Unable to configure ECDSA, no security providers present");
            } else if (providers[0].getName().equals("SunPKCS11-NSS")) {
                /* JcaPEMKeyConverter maintains an internal mapping of
                 * algorithms identifies to string codes. If SunPKCS11-NSS
                 * is the most preferred provider, reflection is used to
                 * adjust that mapping to match the expectations of
                 * SunPKCS11.
                 */
                Field fieldDefinition = JcaPEMKeyConverter.class.getDeclaredField("algorithms");
                fieldDefinition.setAccessible(true);
                Object fieldValue = fieldDefinition.get(null);
                Method put = fieldValue.getClass().getDeclaredMethod("put", Object.class, Object.class);
                put.invoke(fieldValue, X9ObjectIdentifiers.id_ecPublicKey, "EC");
            }
        } catch (ReflectiveOperationException e) {
            System.err.println("SunPKCS11-NSS is preferred security provider, "
                               + "but failed to enable for ECDSA via reflection");
            e.printStackTrace();
        }
    }
}
