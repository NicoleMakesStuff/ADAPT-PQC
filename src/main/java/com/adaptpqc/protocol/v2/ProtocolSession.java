package com.adaptpqc.protocol.v2;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/** Holds active and pending session key material for one peer. */
public final class ProtocolSession {
    private ProtocolCrypto.KeyMaterial active;
    private ProtocolCrypto.KeyMaterial pending;

    public ProtocolSession(byte[] initialSharedSecret, byte[] salt)
            throws GeneralSecurityException {
        if (initialSharedSecret == null || initialSharedSecret.length == 0)
            throw new IllegalArgumentException("Initial shared secret is required");
        if (salt == null || salt.length == 0)
            throw new IllegalArgumentException("Initial salt is required");
        active = ProtocolCrypto.derive(initialSharedSecret, salt, 0);
    }

    public synchronized int generation() {
        return active.generation();
    }

    public synchronized boolean hasPendingKeys() {
        return pending != null;
    }

    synchronized byte[] activeAuthKey() {
        return active.authKey();
    }

    synchronized byte[] pendingAuthKey() {
        if (pending == null) throw new IllegalStateException("No pending keys");
        return pending.authKey();
    }

    synchronized void preparePending(byte[] sharedSecret, byte[] salt, int generation)
            throws GeneralSecurityException {
        if (pending != null) throw new IllegalStateException("Ratchet already pending");
        if (generation != active.generation() + 1)
            throw new IllegalArgumentException("Unexpected next generation");
        pending = ProtocolCrypto.derive(sharedSecret, salt, generation);
    }

    synchronized void commitPending() {
        if (pending == null) throw new IllegalStateException("No pending keys");
        ProtocolCrypto.KeyMaterial old = active;
        active = pending;
        pending = null;
        old.destroy();
    }

    synchronized void abortPending() {
        if (pending != null) pending.destroy();
        pending = null;
    }

    public synchronized ProtocolCrypto.EncryptedPayload encrypt(String message)
            throws GeneralSecurityException {
        byte[] aad = ProtocolCrypto.encode("ADAPT-PQC/v2/chat",
                Integer.toString(active.generation()).getBytes(StandardCharsets.UTF_8));
        return ProtocolCrypto.encrypt(active.aesKey(),
                message.getBytes(StandardCharsets.UTF_8), aad);
    }

    public synchronized String decrypt(ProtocolCrypto.EncryptedPayload payload,
                                       int generation)
            throws GeneralSecurityException {
        if (generation != active.generation())
            throw new GeneralSecurityException("Message has wrong key generation");
        byte[] aad = ProtocolCrypto.encode("ADAPT-PQC/v2/chat",
                Integer.toString(generation).getBytes(StandardCharsets.UTF_8));
        return new String(ProtocolCrypto.decrypt(active.aesKey(), payload, aad),
                StandardCharsets.UTF_8);
    }

    public synchronized void abort() {
        abortPending();
    }
}
