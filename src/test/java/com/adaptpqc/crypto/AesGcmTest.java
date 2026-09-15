package com.adaptpqc.crypto;

import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

public class AesGcmTest {

    @Test
    void encryptionAndDecryptionShouldWork() throws Exception {

        AesGcmManager aes =
                new AesGcmManager();

        SecretKey key =
                aes.generateKey();

        byte[] nonce =
                aes.generateNonce();

        String originalMessage =
                "Hello Bob";

        byte[] plaintext =
                originalMessage.getBytes(
                        StandardCharsets.UTF_8
                );

        byte[] ciphertext =
                aes.encrypt(
                        plaintext,
                        key,
                        nonce
                );

        byte[] decrypted =
                aes.decrypt(
                        ciphertext,
                        key,
                        nonce
                );

        assertArrayEquals(
                plaintext,
                decrypted
        );
    }

    @Test
    void modifiedCiphertextShouldFailAuthentication()
            throws Exception {

        AesGcmManager aes =
                new AesGcmManager();

        SecretKey key =
                aes.generateKey();

        byte[] nonce =
                aes.generateNonce();

        byte[] plaintext =
                "Hello Bob".getBytes(
                        StandardCharsets.UTF_8
                );

        byte[] ciphertext =
                aes.encrypt(
                        plaintext,
                        key,
                        nonce
                );

        // Modify one byte.
        ciphertext[0] ^= 1;

        assertThrows(
                Exception.class,
                () -> aes.decrypt(
                        ciphertext,
                        key,
                        nonce
                )
        );
    }
}