package com.adaptpqc.protocol.v2;

import java.util.UUID;

public final class SecureMessage {
    private final UUID sessionId;
    private final long sequenceNumber;
    private final int generation;
    private final ProtocolCrypto.EncryptedPayload payload;
    private final byte[] authenticationTag;

    public SecureMessage(
            UUID sessionId,
            long sequenceNumber,
            int generation,
            ProtocolCrypto.EncryptedPayload payload,
            byte[] authenticationTag) {

        if (sessionId == null || payload == null) {
            throw new IllegalArgumentException(
                    "Session ID and payload are required");
        }
        if (sequenceNumber < 0 || generation < 0) {
            throw new IllegalArgumentException(
                    "Sequence and generation must be non-negative");
        }
        if (authenticationTag == null || authenticationTag.length == 0) {
            throw new IllegalArgumentException(
                    "Authentication tag is required");
        }

        this.sessionId = sessionId;
        this.sequenceNumber = sequenceNumber;
        this.generation = generation;
        this.payload = payload;
        this.authenticationTag = authenticationTag.clone();
    }

    public UUID sessionId() {
        return sessionId;
    }

    public long sequenceNumber() {
        return sequenceNumber;
    }

    public int generation() {
        return generation;
    }

    ProtocolCrypto.EncryptedPayload payload() {
        return payload;
    }

    public byte[] authenticationTag() {
        return authenticationTag.clone();
    }

    byte[] authenticatedBytes() {
        return ProtocolCrypto.encode(
                "ADAPT-PQC/v2/secure-message",
                ProtocolCrypto.uuidBytes(sessionId),
                java.nio.ByteBuffer.allocate(Long.BYTES)
                        .putLong(sequenceNumber).array(),
                java.nio.ByteBuffer.allocate(Integer.BYTES)
                        .putInt(generation).array(),
                payload.nonce(),
                payload.ciphertext());
    }
}