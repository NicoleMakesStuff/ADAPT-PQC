
package com.adaptpqc.protocol.v2;

import java.security.GeneralSecurityException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

class ProtocolSecurityEvaluationTest {

    private static final byte[] SECRET = new byte[32];
    private static final byte[] SALT = new byte[32];

    private static final UUID SESSION_ID =
            UUID.fromString("12345678-1234-1234-1234-123456789012");

    private SecureMessageService createService()
            throws GeneralSecurityException {

        ProtocolSession session =
                new ProtocolSession(SECRET.clone(), SALT.clone());

        return new SecureMessageService(SESSION_ID, session);
    }

    @Test
    void legitimateMessageShouldBeAccepted()
            throws GeneralSecurityException {

        SecureMessageService sender = createService();
        SecureMessageService receiver = createService();

        SecureMessage message = sender.encrypt("Hello Bob!");

        String plaintext = receiver.decrypt(message);

        assertEquals("Hello Bob!", plaintext);
    }

    @Test
    void replayedMessageShouldBeRejected()
            throws GeneralSecurityException {

        SecureMessageService sender = createService();
        SecureMessageService receiver = createService();

        SecureMessage message = sender.encrypt("Hello Bob!");

        // First delivery must succeed.
        assertEquals("Hello Bob!", receiver.decrypt(message));

        // Second delivery of the same message must fail.
        GeneralSecurityException exception = assertThrows(
                GeneralSecurityException.class,
                () -> receiver.decrypt(message)
        );

        assertNotNull(exception);
    }

    @Test
    void tamperedAuthenticationTagShouldBeRejected()
            throws GeneralSecurityException {

        SecureMessageService sender = createService();
        SecureMessageService receiver = createService();

        SecureMessage original =
                sender.encrypt("Sensitive message");

        byte[] alteredTag = original.authenticationTag();
        alteredTag[0] ^= 0x01;

        SecureMessage tampered = new SecureMessage(
                original.sessionId(),
                original.sequenceNumber(),
                original.generation(),
                original.payload(),
                alteredTag
        );

        GeneralSecurityException exception = assertThrows(
                GeneralSecurityException.class,
                () -> receiver.decrypt(tampered)
        );

        assertNotNull(exception);
    }

    @Test
    void rejectedReplayMustNotAdvanceReceiverSequence()
            throws GeneralSecurityException {

        SecureMessageService sender = createService();
        SecureMessageService receiver = createService();

        SecureMessage first = sender.encrypt("Message one");
        SecureMessage second = sender.encrypt("Message two");

        assertEquals("Message one", receiver.decrypt(first));

        // Replaying the first message must fail.
        GeneralSecurityException exception = assertThrows(
                GeneralSecurityException.class,
                () -> receiver.decrypt(first)
        );

        assertNotNull(exception);

        // A valid subsequent message must still be accepted.
        assertEquals("Message two", receiver.decrypt(second));
    }
}
