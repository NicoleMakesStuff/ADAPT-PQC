package com.adaptpqc.crypto;

public class KemEncapsulationResult {

    private final byte[] ciphertext;
    private final byte[] sharedSecret;

    public KemEncapsulationResult(
            byte[] ciphertext,
            byte[] sharedSecret) {

        this.ciphertext = ciphertext;
        this.sharedSecret = sharedSecret;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }
}