package com.adaptpqc.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import org.junit.jupiter.api.Test;

public class HkdfTest {

    @Test
    void sameInputsShouldProduceSameKey()
            throws Exception {

        HkdfManager hkdf =
                new HkdfManager();

        byte[] secret =
                "test shared secret".getBytes(
                        StandardCharsets.UTF_8
                );

        byte[] salt =
                "test salt".getBytes(
                        StandardCharsets.UTF_8
                );

        byte[] key1 =
                hkdf.deriveKey(
                        secret,
                        salt,
                        "ADAPT-PQC-ENCRYPTION",
                        32
                );

        byte[] key2 =
                hkdf.deriveKey(
                        secret,
                        salt,
                        "ADAPT-PQC-ENCRYPTION",
                        32
                );

        assertArrayEquals(
                key1,
                key2
        );
    }

    @Test
    void differentInfoShouldProduceDifferentKeys()
            throws Exception {

        HkdfManager hkdf =
                new HkdfManager();

        byte[] secret =
                "test shared secret".getBytes(
                        StandardCharsets.UTF_8
                );

        byte[] salt =
                "test salt".getBytes(
                        StandardCharsets.UTF_8
                );

        byte[] encryptionKey =
                hkdf.deriveKey(
                        secret,
                        salt,
                        "ADAPT-PQC-ENCRYPTION",
                        32
                );

        byte[] ratchetKey =
                hkdf.deriveKey(
                        secret,
                        salt,
                        "ADAPT-PQC-RATCHET",
                        32
                );

        assertFalse(
                Arrays.equals(
                        encryptionKey,
                        ratchetKey
                )
        );
    }

    @Test
    void hkdfShouldProduceRequestedLength()
            throws Exception {

        HkdfManager hkdf =
                new HkdfManager();

        byte[] secret =
                "shared secret".getBytes(
                        StandardCharsets.UTF_8
                );

        byte[] key =
                hkdf.deriveKey(
                        secret,
                        null,
                        "ADAPT-PQC-TEST",
                        32
                );

        assertEquals(
                32,
                key.length
        );
    }
}