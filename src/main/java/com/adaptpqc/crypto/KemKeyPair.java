package com.adaptpqc.crypto;

public class KemKeyPair {

    private final byte[] publicKey;
    private final byte[] privateKey;

    public KemKeyPair(
            byte[] publicKey,
            byte[] privateKey) {

        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }
}