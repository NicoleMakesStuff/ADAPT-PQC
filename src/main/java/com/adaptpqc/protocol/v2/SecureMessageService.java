package com.adaptpqc.protocol.v2;

import java.security.GeneralSecurityException;
import java.util.UUID;

public final class SecureMessageService {

    private final UUID sessionId;
    private final ProtocolSession session;
    private final MessageSequenceTracker receiverTracker =
            new MessageSequenceTracker();

    private long nextOutgoingSequence = 0;

    public SecureMessageService(
            UUID sessionId,
            ProtocolSession session) {

        if (sessionId == null || session == null) {
            throw new IllegalArgumentException(
                    "Session ID and protocol session are required");
        }

        this.sessionId = sessionId;
        this.session = session;
    }

    public synchronized SecureMessage encrypt(
            String plaintext) throws GeneralSecurityException {

        if (plaintext == null) {
            throw new IllegalArgumentException(
                    "Plaintext must not be null");
        }

        if (nextOutgoingSequence == Long.MAX_VALUE) {
            throw new GeneralSecurityException(
                    "Sequence exhausted; re-establish session");
        }

        long sequence = nextOutgoingSequence;
        int generation = session.generation();

        ProtocolCrypto.EncryptedPayload encrypted =
                session.encrypt(plaintext);

        SecureMessage unsigned = new SecureMessage(
                sessionId,
                sequence,
                generation,
                encrypted,
                new byte[]{1});

        byte[] tag = ProtocolCrypto.mac(
                session.activeAuthKey(),
                unsigned.authenticatedBytes());

        SecureMessage message = new SecureMessage(
                sessionId,
                sequence,
                generation,
                encrypted,
                tag);

        nextOutgoingSequence++;
        return message;
    }

    public synchronized String decrypt(
            SecureMessage message) throws GeneralSecurityException {

        if (message == null) {
            throw new ProtocolRejectionException(
                    ProtocolRejectionReason.NULL_MESSAGE,
                    "Message is null");
        }

        if (!sessionId.equals(message.sessionId())) {
            throw new ProtocolRejectionException(
                    ProtocolRejectionReason.WRONG_SESSION,
                    "Wrong session ID");
        }

        if (message.generation() != session.generation()) {
            throw new ProtocolRejectionException(
                    ProtocolRejectionReason.WRONG_GENERATION,
                    "Wrong key generation");
        }

        if (!receiverTracker.isExpected(message.sequenceNumber())) {
            throw new ProtocolRejectionException(
                    ProtocolRejectionReason.REPLAY_OR_OUT_OF_ORDER,
                    "Replay or out-of-order message detected");
        }

        // Authenticate metadata, nonce and ciphertext before decryption.
        if (!ProtocolCrypto.verifyMac(
                session.activeAuthKey(),
                message.authenticatedBytes(),
                message.authenticationTag())) {
            throw new ProtocolRejectionException(
                    ProtocolRejectionReason.AUTHENTICATION_FAILED,
                    "Message authentication failed");
        }

        String plaintext;

        try {
            plaintext = session.decrypt(
                    message.payload(),
                    message.generation());
        } catch (GeneralSecurityException e) {
            throw new ProtocolRejectionException(
                    ProtocolRejectionReason.DECRYPTION_FAILED,
                    "Message decryption failed",
                    e);
        }

        // Advance sequence only after authentication and decryption succeed.
        receiverTracker.markAccepted(message.sequenceNumber());

        return plaintext;
    }
}
