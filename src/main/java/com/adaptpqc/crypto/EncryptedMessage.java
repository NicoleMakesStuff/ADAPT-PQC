package com.adaptpqc.crypto;

public class EncryptedMessage {

    private final byte[] nonce;
    private final byte[] ciphertext;

    public EncryptedMessage(
            byte[] nonce,
            byte[] ciphertext) {

        this.nonce = nonce;
        this.ciphertext = ciphertext;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }
}