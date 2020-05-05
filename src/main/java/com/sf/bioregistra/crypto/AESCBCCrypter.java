package com.sf.bioregistra.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.TimeZone;

@Deprecated
public final class AESCBCCrypter {

    private static final Logger logger = LoggerFactory.getLogger(AESCBCCrypter.class);

    private AESCBCCrypter() {
        throw new IllegalStateException("Class cannot be instantiated");
    }

    public static void main(String[] args) {
        String key = "9Maqi7VgCbzh9CcDj0eP";
        String clean = "WIN-12345:" + System.currentTimeMillis() + ":" + TimeZone.getDefault().getID();
        try {
            String encrypted = encrypt(clean, key);
            long sysTime = System.currentTimeMillis();
            String decrypted = decrypt(encrypted, key);
            if (logger.isDebugEnabled()) {
                logger.debug("Decrypted: {}", decrypted);
                logger.debug("Time taken to decrypt: {}", (System.currentTimeMillis() - sysTime) + "ms");
            }
        } catch (GeneralSecurityException | UnsupportedEncodingException e) {
            logger.error(e.getMessage());
        }
    }

    public static String encrypt(String plainText, String key) throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] clean = plainText.getBytes();

        // Generating IV.
        int ivSize = 16;
        byte[] ivBytes = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        // Hashing key.
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        digest.update(key.getBytes("UTF-8"));
        byte[] keyBytes = new byte[16];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        // Encrypt.
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(clean);

        // Combine IV and encrypted part.
        byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
        System.arraycopy(ivBytes, 0, encryptedIVAndText, 0, ivSize);
        System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);

        return Base64.getEncoder().encodeToString(encryptedIVAndText);
    }

    public static String decrypt(String cipherText, String key) throws GeneralSecurityException {
        int ivSize = 16;
        int keySize = 16;
        byte[] encryptedIvTextBytes = Base64.getDecoder().decode(cipherText);

        // Extract IV.
        byte[] ivBytes = new byte[ivSize];
        System.arraycopy(encryptedIvTextBytes, 0, ivBytes, 0, ivBytes.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        // Extract encrypted part.
        int encryptedSize = encryptedIvTextBytes.length - ivSize;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedIvTextBytes, ivSize, encryptedBytes, 0, encryptedSize);

        // Hash key.
        byte[] keyBytes = new byte[keySize];
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
        messageDigest.update(key.getBytes());
        System.arraycopy(messageDigest.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        // Decrypt.
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

        return new String(decrypted);
    }
}
