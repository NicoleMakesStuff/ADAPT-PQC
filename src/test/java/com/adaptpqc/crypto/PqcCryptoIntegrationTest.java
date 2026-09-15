package com.adaptpqc.crypto;

import java.security.KeyPair;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

class PqcCryptoIntegrationTest {

    @Test
    void mlKemHkdfAesGcmPipelineShouldWork()
            throws Exception {

        /*
         * STEP 1
         * Bob generates ML-KEM-768 keys.
         */
        KemManager kem =
                new KemManager();

        KeyPair bobKeys =
                kem.generateKeyPair();


        /*
         * STEP 2
         * Alice encapsulates using Bob's public key.
         */
        KemEncapsulationResult encapsulated =
                kem.encapsulate(
                        bobKeys.getPublic()
                );


        /*
         * STEP 3
         * Bob decapsulates.
         */
        byte[] bobSharedSecret =
                kem.decapsulate(
                        bobKeys.getPrivate(),
                        encapsulated.getCiphertext()
                );


        /*
         * STEP 4
         * Verify that both sides have the same
         * ML-KEM shared secret.
         */
        assertArrayEquals(
                encapsulated.getSharedSecret(),
                bobSharedSecret
        );


        /*
         * STEP 5
         * Generate a public HKDF salt.
         */
        byte[] salt =
                new byte[32];

        new SecureRandom().nextBytes(salt);


        /*
         * STEP 6
         * Alice creates her crypto session.
         */
        CryptoSession aliceSession =
                new CryptoSession(
                        encapsulated.getSharedSecret(),
                        salt
                );


        /*
         * STEP 7
         * Bob creates his crypto session.
         */
        CryptoSession bobSession =
                new CryptoSession(
                        bobSharedSecret,
                        salt
                );


        /*
         * STEP 8
         * Alice encrypts a message.
         */
        String originalMessage =
                "Hello Bob! This message is protected by ADAPT-PQC.";

        EncryptedMessage encrypted =
                aliceSession.encrypt(
                        originalMessage
                );


        /*
         * STEP 9
         * Bob decrypts the message.
         */
        String decryptedMessage =
                bobSession.decrypt(
                        encrypted
                );


        /*
         * STEP 10
         * Verify end-to-end correctness.
         */
        assertEquals(
                originalMessage,
                decryptedMessage
        );
    }


    @Test
    void modifiedCiphertextShouldBeRejected()
            throws Exception {

        KemManager kem =
                new KemManager();

        KeyPair bobKeys =
                kem.generateKeyPair();

        KemEncapsulationResult encapsulated =
                kem.encapsulate(
                        bobKeys.getPublic()
                );

        byte[] bobSharedSecret =
                kem.decapsulate(
                        bobKeys.getPrivate(),
                        encapsulated.getCiphertext()
                );

        byte[] salt =
                new byte[32];

        new SecureRandom().nextBytes(salt);

        CryptoSession aliceSession =
                new CryptoSession(
                        encapsulated.getSharedSecret(),
                        salt
                );

        CryptoSession bobSession =
                new CryptoSession(
                        bobSharedSecret,
                        salt
                );

        EncryptedMessage encrypted =
                aliceSession.encrypt(
                        "Secret message"
                );


        /*
         * Simulate an attacker modifying
         * the ciphertext.
         */
        byte[] modifiedCiphertext =
                encrypted.getCiphertext().clone();

        modifiedCiphertext[0] ^= 1;


        EncryptedMessage tamperedMessage =
                new EncryptedMessage(
                        encrypted.getNonce(),
                        modifiedCiphertext
                );


        /*
         * AES-GCM authentication should detect
         * the modification.
         */
        assertThrows(
                Exception.class,
                () -> bobSession.decrypt(
                        tamperedMessage
                )
        );
    }
}