/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

import org.testng.annotations.DataProvider;

public class SignerDSATest extends SignerTest {

    @Override
    public String getKeyCode() {
        return "dsa_1024";
    }

    @Override
    @DataProvider(name = "testData")
    public Object[][] testData() {
        String[] hashes = {"SHA1", "SHA256"};
        String[] providerCodes = {"stdlib"};
        return permuteParameters(hashes, providerCodes);
    }
}
