/*
 * Copyright (c) 2017, Joyent, Inc. All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.joyent.http.signature;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.List;
import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class SignerRSATest extends SignerTest {

    @Override
    public String getKeyCode() {
        return "rsa_2048";
    }

    @Override
    @DataProvider(name = "testData")
    public Object[][] testData() {
        String[] hashes = {"SHA1", "SHA256", "SHA512"};
        String[] providerCodes = {"stdlib", "native.jnagmp"};
        return permuteParameters(hashes, providerCodes);
    }
}
