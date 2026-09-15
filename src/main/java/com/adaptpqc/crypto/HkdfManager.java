package com.adaptpqc.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HkdfManager {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final SecureRandom secureRandom;

    public HkdfManager() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * HKDF-Extract.
     *
     * PRK = HMAC-SHA256(salt, inputKeyMaterial)
     */
    public byte[] extract(
            byte[] salt,
            byte[] inputKeyMaterial) throws Exception {

        if (salt == null || salt.length == 0) {

            salt = new byte[32];

        }

        Mac mac = Mac.getInstance(HMAC_ALGORITHM);

        SecretKeySpec saltKey =
                new SecretKeySpec(salt, HMAC_ALGORITHM);

        mac.init(saltKey);

        return mac.doFinal(inputKeyMaterial);
    }

    /**
     * HKDF-Expand.
     *
     * Produces the requested number of output bytes.
     */
    public byte[] expand(
            byte[] pseudoRandomKey,
            byte[] info,
            int outputLength) throws Exception {

        if (outputLength <= 0) {
            throw new IllegalArgumentException(
                    "Output length must be greater than zero."
            );
        }

        Mac mac = Mac.getInstance(HMAC_ALGORITHM);

        SecretKeySpec key =
                new SecretKeySpec(
                        pseudoRandomKey,
                        HMAC_ALGORITHM
                );

        mac.init(key);

        int hashLength = 32;

        int numberOfBlocks =
                (int) Math.ceil(
                        (double) outputLength / hashLength
                );

        if (numberOfBlocks > 255) {
            throw new IllegalArgumentException(
                    "HKDF output length is too large."
            );
        }

        byte[] result = new byte[outputLength];

        byte[] previousBlock = new byte[0];

        int resultOffset = 0;

        for (int i = 1; i <= numberOfBlocks; i++) {

            mac.reset();

            mac.update(previousBlock);

            if (info != null) {
                mac.update(info);
            }

            mac.update((byte) i);

            previousBlock = mac.doFinal();

            int bytesToCopy =
                    Math.min(
                            hashLength,
                            outputLength - resultOffset
                    );

            System.arraycopy(
                    previousBlock,
                    0,
                    result,
                    resultOffset,
                    bytesToCopy
            );

            resultOffset += bytesToCopy;
        }

        return result;
    }

    /**
     * Convenience method:
     *
     * input secret
     *      ↓
     * HKDF-Extract
     *      ↓
     * HKDF-Expand
     */
    public byte[] deriveKey(
            byte[] inputKeyMaterial,
            byte[] salt,
            String info,
            int outputLength) throws Exception {

        byte[] pseudoRandomKey =
                extract(
                        salt,
                        inputKeyMaterial
                );

        byte[] infoBytes =
                info == null
                        ? new byte[0]
                        : info.getBytes(StandardCharsets.UTF_8);

        return expand(
                pseudoRandomKey,
                infoBytes,
                outputLength
        );
    }

    /**
     * Generates a random salt.
     */
    public byte[] generateSalt() {

        byte[] salt = new byte[32];

        secureRandom.nextBytes(salt);

        return salt;
    }
}