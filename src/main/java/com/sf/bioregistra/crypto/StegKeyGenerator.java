package com.sf.bioregistra.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Properties;

public class StegKeyGenerator {

    private static final Logger LOGGER  = LoggerFactory.getLogger(StegKeyGenerator.class);

    private String key;

    public StegKeyGenerator(String cipherKeyFile, String authSalt) {
        this("", cipherKeyFile, authSalt);
    }

    public StegKeyGenerator(String stegDirPath, String cipherKeyFile, String authSalt) {
        File secretDir = new File(stegDirPath);
        if (!secretDir.exists()) {
            LOGGER.info("Defaulting to internal steg prep folder");
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            String path = classLoader.getResource("steg-prep").getPath();
            secretDir = new File(path);
        }
        secretDir.mkdirs();
        File encodeDir = new File(secretDir, "encode-result");
        encodeDir.mkdirs();
        File revealDir = new File(secretDir, "reveal-result");
        revealDir.mkdirs();

        StegUtil stegUtil = new StegUtil();
        try {
            stegUtil.reveal(encodeDir, revealDir, null);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | IllegalStateException | ShortBufferException | IllegalBlockSizeException | BadPaddingException | IOException | InvalidKeyException exception) {
            LOGGER.error("Failed to decode Steg file: {}", exception.getMessage());
        }

        File secret = new File(revealDir, "steg-prep.properties");
        Properties props = new Properties();
        try {
            props.load(Files.newInputStream(Paths.get(secret.getPath())));
            key = props.getProperty(cipherKeyFile, authSalt);
        } catch (IOException exception) {
            LOGGER.error("Error loading props file: {}", exception.getMessage());
        }
        secret.delete();
        revealDir.delete();
    }

    public String getKey() {
        return key;
    }

}
