package com.joyent.http.signature;

import com.squareup.crypto.rsa.NativeRSAEngine;
import org.bouncycastle.crypto.engines.RSABlindedEngine;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;

/**
 * Created by elijah on 1/1/16.
 */
public class NativeRSABlindedEngine extends RSABlindedEngine {
    {
        Class clazz = RSABlindedEngine.class;

        try {
            Field field = clazz.getDeclaredField("core");
            field.setAccessible(true);
            field.set(this, getNativeRSACoreEngineInstance());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Object getNativeRSACoreEngineInstance() throws NoSuchMethodException,
            IllegalAccessException, InstantiationException, InvocationTargetException {
        Class<NativeRSAEngine> clazz = NativeRSAEngine.class;
        Constructor<NativeRSAEngine> constructor = clazz.getConstructor(clazz);
        constructor.setAccessible(true);
        return constructor.newInstance();
    }
}
