package com.sf.bioregistra.crypto;

import java.net.URL;
import org.slf4j.Logger;
import org.keyczar.Crypter;
import org.slf4j.LoggerFactory;
import sfx.crypto.CryptoReader;
import org.keyczar.exceptions.KeyczarException;

public final class Crypto {

    private static final Logger LOGGER = LoggerFactory.getLogger(Crypto.class);

    private static Crypter instance;

    private Crypto() { }

    private static void init(String path) {
        CryptoReader reader;
        try {
            reader = new CryptoReader(path);
        } catch (IllegalAccessError exception) {
            LOGGER.error("Error reading map db folder, defaulting to internal map: {}", exception.getMessage());
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            URL url = classLoader.getResource("map");
            reader = new CryptoReader(url.getPath());
        }
        try {
            instance = new Crypter(reader);
        } catch (KeyczarException exception) {
            LOGGER.error("Error initializing crypter. Exception: {}", exception.getMessage());
        }
    }

    public static Crypter getCrypter() {
        synchronized (Crypto.class) {
            if (instance == null) {
                init("");
            }
        }
        return instance;
    }

    public static Crypter getCrypter(String mapDbPath) {
        synchronized (Crypto.class) {
            if (instance == null) {
                init(mapDbPath);
            }
        }
        return instance;
    }

}
