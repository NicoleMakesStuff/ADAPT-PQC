package com.adaptpqc.protocol.v2;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

class SecureMessageServiceTest {

    private static final byte[] SECRET =
            "test-only-secret-for-message-tests"
                    .getBytes(StandardCharsets.UTF_8);

    private static final byte[] SALT = new byte[32];

    private ProtocolSession newSession() throws Exception {
        return new ProtocolSession(SECRET, SALT);
    }

    @Test
    void encryptsAndDecryptsMessage() throws Exception {
        UUID id = UUID.randomUUID();

        SecureMessageService sender =
                new SecureMessageService(id, newSession());
        SecureMessageService receiver =
                new SecureMessageService(id, newSession());

        SecureMessage message = sender.encrypt("Hello, PQC!");
        assertEquals("Hello, PQC!", receiver.decrypt(message));
    }

    @Test
    void rejectsReplayedMessage() throws Exception {
        UUID id = UUID.randomUUID();

        SecureMessageService sender =
                new SecureMessageService(id, newSession());
        SecureMessageService receiver =
                new SecureMessageService(id, newSession());

        SecureMessage message = sender.encrypt("Only once");

        assertEquals("Only once", receiver.decrypt(message));

        assertThrows(
                java.security.GeneralSecurityException.class,
                () -> receiver.decrypt(message));
    }

    @Test
    void rejectsTamperedCiphertext() throws Exception {
        UUID id = UUID.randomUUID();

        SecureMessageService sender =
                new SecureMessageService(id, newSession());
        SecureMessageService receiver =
                new SecureMessageService(id, newSession());

        SecureMessage original = sender.encrypt("Tamper test");
        byte[] changedCiphertext = original.payload().ciphertext();
        changedCiphertext[0] ^= 1;

        ProtocolCrypto.EncryptedPayload changedPayload =
                new ProtocolCrypto.EncryptedPayload(
                        original.payload().nonce(),
                        changedCiphertext);

        SecureMessage tampered = new SecureMessage(
                original.sessionId(),
                original.sequenceNumber(),
                original.generation(),
                changedPayload,
                original.authenticationTag());

        assertThrows(
                java.security.GeneralSecurityException.class,
                () -> receiver.decrypt(tampered));
    }

    @Test
    void rejectsWrongSessionId() throws Exception {
        SecureMessageService sender =
                new SecureMessageService(
                        UUID.randomUUID(), newSession());

        SecureMessageService receiver =
                new SecureMessageService(
                        UUID.randomUUID(), newSession());

        SecureMessage message = sender.encrypt("Wrong session");

        assertThrows(
                java.security.GeneralSecurityException.class,
                () -> receiver.decrypt(message));
    }

    @Test
    void rejectsModifiedAuthenticationTag() throws Exception {
        UUID id = UUID.randomUUID();

        SecureMessageService sender =
                new SecureMessageService(id, newSession());
        SecureMessageService receiver =
                new SecureMessageService(id, newSession());

        SecureMessage original = sender.encrypt("Authentication test");
        byte[] badTag = original.authenticationTag();
        badTag[0] ^= 1;

        SecureMessage tampered = new SecureMessage(
                original.sessionId(),
                original.sequenceNumber(),
                original.generation(),
                original.payload(),
                badTag);

        assertThrows(
                java.security.GeneralSecurityException.class,
                () -> receiver.decrypt(tampered));
    }
}