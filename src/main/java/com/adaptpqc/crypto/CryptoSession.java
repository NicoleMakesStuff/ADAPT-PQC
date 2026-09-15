package com.adaptpqc.crypto;

import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

public class CryptoSession {

    private static final String HKDF_INFO =
            "ADAPT-PQC-SESSION-AES-256";

    private final AesGcmManager aes;
    private final SecretKey sessionKey;

    /**
     * Creates an AES session key from the
     * ML-KEM shared secret using HKDF.
     */
    public CryptoSession(
            byte[] sharedSecret,
            byte[] salt) throws Exception {

        if (sharedSecret == null || sharedSecret.length == 0) {
            throw new IllegalArgumentException(
                    "Shared secret cannot be empty."
            );
        }

        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException(
                    "Salt cannot be empty."
            );
        }

        HkdfManager hkdf =
                new HkdfManager();

        byte[] aesKeyBytes =
                hkdf.deriveKey(
                        sharedSecret,
                        salt,
                        HKDF_INFO,
                        32
                );

        this.aes =
                new AesGcmManager();

        this.sessionKey =
                aes.keyFromBytes(aesKeyBytes);
    }

    /**
     * Encrypts a plaintext message.
     */
    public EncryptedMessage encrypt(
            String message) throws Exception {

        byte[] plaintext =
                message.getBytes(
                        StandardCharsets.UTF_8
                );

        byte[] nonce =
                aes.generateNonce();

        byte[] ciphertext =
                aes.encrypt(
                        plaintext,
                        sessionKey,
                        nonce
                );

        return new EncryptedMessage(
                nonce,
                ciphertext
        );
    }

    /**
     * Decrypts an encrypted message.
     */
    public String decrypt(
            EncryptedMessage encryptedMessage)
            throws Exception {

        byte[] plaintext =
                aes.decrypt(
                        encryptedMessage.getCiphertext(),
                        sessionKey,
                        encryptedMessage.getNonce()
                );

        return new String(
                plaintext,
                StandardCharsets.UTF_8
        );
    }
}