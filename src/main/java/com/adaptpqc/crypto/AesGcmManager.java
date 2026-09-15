package com.adaptpqc.crypto;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesGcmManager {

    private static final String AES = "AES";
    private static final String AES_GCM = "AES/GCM/NoPadding";

    private static final int KEY_SIZE = 256;
    private static final int NONCE_SIZE = 12;
    private static final int TAG_LENGTH = 128;

    private final SecureRandom secureRandom;

    public AesGcmManager() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Generates a 256-bit AES key.
     */
    public SecretKey generateKey() throws Exception {

        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(KEY_SIZE);

        return keyGenerator.generateKey();
    }

    /**
     * Generates a fresh nonce for AES-GCM.
     */
    public byte[] generateNonce() {

        byte[] nonce = new byte[NONCE_SIZE];

        secureRandom.nextBytes(nonce);

        return nonce;
    }

    /**
     * Encrypts plaintext using AES-GCM.
     *
     * @param plaintext plaintext bytes
     * @param key AES key
     * @param nonce fresh nonce
     * @return ciphertext including authentication tag
     */
    public byte[] encrypt(
            byte[] plaintext,
            SecretKey key,
            byte[] nonce) throws Exception {

        Cipher cipher = Cipher.getInstance(AES_GCM);

        GCMParameterSpec parameterSpec =
                new GCMParameterSpec(TAG_LENGTH, nonce);

        cipher.init(
                Cipher.ENCRYPT_MODE,
                key,
                parameterSpec
        );

        return cipher.doFinal(plaintext);
    }

    /**
     * Decrypts AES-GCM ciphertext.
     *
     * @param ciphertext ciphertext including authentication tag
     * @param key AES key
     * @param nonce nonce used during encryption
     * @return decrypted plaintext
     */
    public byte[] decrypt(
            byte[] ciphertext,
            SecretKey key,
            byte[] nonce) throws Exception {

        Cipher cipher = Cipher.getInstance(AES_GCM);

        GCMParameterSpec parameterSpec =
                new GCMParameterSpec(TAG_LENGTH, nonce);

        cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                parameterSpec
        );

        return cipher.doFinal(ciphertext);
    }

    /**
     * Converts raw key bytes into a SecretKey.
     */
    public SecretKey keyFromBytes(byte[] keyBytes) {

        return new SecretKeySpec(keyBytes, AES);
    }
}