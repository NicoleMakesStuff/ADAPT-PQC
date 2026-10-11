package com.adaptpqc.protocol.v2;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class ProtocolCrypto {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int AES_KEY_BYTES = 32;
    private static final int AUTH_KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    private ProtocolCrypto() {}

    static byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }

    static KeyMaterial derive(byte[] sharedSecret, byte[] salt, int generation)
            throws GeneralSecurityException {
        byte[] prk = hmac(salt, sharedSecret);
        byte[] aes = hkdfExpand(prk,
                ("ADAPT-PQC/v2/AES-GCM/generation/" + generation)
                        .getBytes(StandardCharsets.UTF_8), AES_KEY_BYTES);
        byte[] auth = hkdfExpand(prk,
                ("ADAPT-PQC/v2/HMAC-SHA256/generation/" + generation)
                        .getBytes(StandardCharsets.UTF_8), AUTH_KEY_BYTES);
        Arrays.fill(prk, (byte) 0);
        return new KeyMaterial(aes, auth, generation);
    }

    // HKDF-Expand (RFC 5869), SHA-256.
    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length)
            throws GeneralSecurityException {
        byte[] output = new byte[length];
        byte[] previous = new byte[0];
        int offset = 0;
        int counter = 1;
        while (offset < length) {
            ByteArrayOutputStream input = new ByteArrayOutputStream();
            input.writeBytes(previous);
            input.writeBytes(info);
            input.write(counter);
            previous = hmac(prk, input.toByteArray());
            int n = Math.min(previous.length, length - offset);
            System.arraycopy(previous, 0, output, offset, n);
            offset += n;
            counter++;
        }
        Arrays.fill(previous, (byte) 0);
        return output;
    }

    private static byte[] hmac(byte[] key, byte[] data)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    static byte[] mac(byte[] authKey, byte[] data)
            throws GeneralSecurityException {
        return hmac(authKey, data);
    }

    static boolean verifyMac(byte[] authKey, byte[] data, byte[] expected)
            throws GeneralSecurityException {
        return MessageDigest.isEqual(hmac(authKey, data), expected);
    }

    static EncryptedPayload encrypt(byte[] aesKey, byte[] plaintext, byte[] aad)
            throws GeneralSecurityException {
        byte[] nonce = randomBytes(NONCE_BYTES);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(aesKey, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, nonce));
        cipher.updateAAD(aad);
        return new EncryptedPayload(nonce, cipher.doFinal(plaintext));
    }

    static byte[] decrypt(byte[] aesKey, EncryptedPayload payload, byte[] aad)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(aesKey, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, payload.nonce()));
        cipher.updateAAD(aad);
        return cipher.doFinal(payload.ciphertext());
    }

    static byte[] encode(String domain, byte[]... fields) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            byte[] domainBytes = domain.getBytes(StandardCharsets.UTF_8);
            out.writeInt(domainBytes.length);
            out.write(domainBytes);
            for (byte[] field : fields) {
                out.writeInt(field.length);
                out.write(field);
            }
            out.flush();
            return bytes.toByteArray();
        } catch (java.io.IOException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    static byte[] uuidBytes(java.util.UUID id) {
        return java.nio.ByteBuffer.allocate(16)
                .putLong(id.getMostSignificantBits())
                .putLong(id.getLeastSignificantBits()).array();
    }

    record KeyMaterial(byte[] aesKey, byte[] authKey, int generation) {
        KeyMaterial {
            aesKey = aesKey.clone();
            authKey = authKey.clone();
        }
        @Override public byte[] aesKey() { return aesKey.clone(); }
        @Override public byte[] authKey() { return authKey.clone(); }
        void destroy() {
            Arrays.fill(aesKey, (byte) 0);
            Arrays.fill(authKey, (byte) 0);
        }
    }

    record EncryptedPayload(byte[] nonce, byte[] ciphertext) {
        EncryptedPayload {
            nonce = nonce.clone();
            ciphertext = ciphertext.clone();
        }
        @Override public byte[] nonce() { return nonce.clone(); }
        @Override public byte[] ciphertext() { return ciphertext.clone(); }
    }
}
