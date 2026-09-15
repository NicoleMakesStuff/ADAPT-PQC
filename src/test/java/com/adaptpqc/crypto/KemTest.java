package com.adaptpqc.crypto;

import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.Test;

class KemTest {

    @Test
    void mlKem768EncapsulationAndDecapsulationShouldMatch()
            throws Exception {

        KemManager kem =
                new KemManager();

        // Bob generates his ML-KEM-768 key pair
        KeyPair bobKeys =
                kem.generateKeyPair();

        assertNotNull(bobKeys);
        assertNotNull(bobKeys.getPublic());
        assertNotNull(bobKeys.getPrivate());

        // Alice encapsulates using Bob's public key
        KemEncapsulationResult result =
                kem.encapsulate(
                        bobKeys.getPublic()
                );

        assertNotNull(result);
        assertNotNull(result.getCiphertext());
        assertNotNull(result.getSharedSecret());

        // Bob decapsulates using his private key
        byte[] bobSecret =
                kem.decapsulate(
                        bobKeys.getPrivate(),
                        result.getCiphertext()
                );

        // Alice and Bob must obtain the same secret
        assertArrayEquals(
                result.getSharedSecret(),
                bobSecret
        );
    }


    @Test
    void differentEncapsulationsShouldProduceDifferentCiphertexts()
            throws Exception {

        KemManager kem =
                new KemManager();

        KeyPair bobKeys =
                kem.generateKeyPair();

        KemEncapsulationResult result1 =
                kem.encapsulate(
                        bobKeys.getPublic()
                );

        KemEncapsulationResult result2 =
                kem.encapsulate(
                        bobKeys.getPublic()
                );

        assertFalse(
                Arrays.equals(
                        result1.getCiphertext(),
                        result2.getCiphertext()
                )
        );
    }
}