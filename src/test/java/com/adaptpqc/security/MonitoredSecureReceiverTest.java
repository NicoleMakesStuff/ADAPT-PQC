package com.adaptpqc.security;

import java.security.GeneralSecurityException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.adaptpqc.protocol.v2.ProtocolRejectionReason;
import com.adaptpqc.protocol.v2.ProtocolSession;
import com.adaptpqc.protocol.v2.ProtocolTestSupport;
import com.adaptpqc.protocol.v2.SecureMessage;
import com.adaptpqc.protocol.v2.SecureMessageService;
import com.adaptpqc.ratchet.RatchetController;
import com.adaptpqc.ratchet.RatchetDecision;
import com.adaptpqc.session.SessionState;

class MonitoredSecureReceiverTest {

    private static final byte[] SECRET = new byte[32];
    private static final byte[] SALT = new byte[32];

    private static final UUID SESSION_ID =
            UUID.fromString("12345678-1234-1234-1234-123456789012");

    private SecureMessageService sender;
    private SessionState sessionState;
    private SecurityMonitor monitor;
    private MonitoredSecureReceiver receiver;

    private static SecureMessageService createService(UUID id)
            throws GeneralSecurityException {

        return new SecureMessageService(
                id,
                new ProtocolSession(SECRET.clone(), SALT.clone()));
    }

    @BeforeEach
    void setUp() throws GeneralSecurityException {
        sender = createService(SESSION_ID);

        sessionState = new SessionState();
        monitor = new SecurityMonitor(sessionState);

        receiver = new MonitoredSecureReceiver(
                createService(SESSION_ID),
                sessionState,
                monitor,
                new RatchetController());
    }

    @Test
    void legitimateMessageRecordsNoSecurityEvent()
            throws GeneralSecurityException {

        ReceiveResult result = receiver.receive(sender.encrypt("hello"));

        assertTrue(result.accepted());
        assertEquals("hello", result.plaintext());
        assertNull(result.rejectionReason());
        assertEquals(0, monitor.getEventCount());
        assertEquals(1, sessionState.getMessageCount());
        assertEquals(SecurityState.NORMAL, monitor.getCurrentState());
    }

    @Test
    void replayIsClassifiedAsReplayAttemptExactlyOnce()
            throws GeneralSecurityException {

        SecureMessage message = sender.encrypt("once");

        assertTrue(receiver.receive(message).accepted());

        ReceiveResult replay = receiver.receive(message);

        assertFalse(replay.accepted());
        assertEquals(ProtocolRejectionReason.REPLAY_OR_OUT_OF_ORDER,
                replay.rejectionReason());
        assertEquals(SecurityEventType.REPLAY_ATTEMPT,
                replay.eventType());
        assertEquals(1, monitor.getEventCount());
        assertTrue(monitor.getCurrentRisk() > 0.0);
    }

    @Test
    void badTagIsClassifiedAsCiphertextTampering()
            throws GeneralSecurityException {

        SecureMessage tampered = ProtocolTestSupport
                .tamperAuthenticationTag(sender.encrypt("secret"));

        ReceiveResult result = receiver.receive(tampered);

        assertFalse(result.accepted());
        assertEquals(ProtocolRejectionReason.AUTHENTICATION_FAILED,
                result.rejectionReason());
        assertEquals(SecurityEventType.CIPHERTEXT_TAMPERING,
                result.eventType());
        assertEquals(1, monitor.getEventCount());
    }

    @Test
    void wrongSessionIsClassifiedAsAuthenticationFailure()
            throws GeneralSecurityException {

        SecureMessageService stranger =
                createService(UUID.randomUUID());

        ReceiveResult result = receiver.receive(stranger.encrypt("hi"));

        assertEquals(ProtocolRejectionReason.WRONG_SESSION,
                result.rejectionReason());
        assertEquals(SecurityEventType.AUTHENTICATION_FAILURE,
                result.eventType());
        assertEquals(1, monitor.getEventCount());
    }

    @Test
    void staleGenerationIsOnlyATrafficAnomaly()
            throws GeneralSecurityException {

        SecureMessage wrongGeneration = ProtocolTestSupport
                .withGeneration(sender.encrypt("late"), 7);

        ReceiveResult result = receiver.receive(wrongGeneration);

        assertEquals(ProtocolRejectionReason.WRONG_GENERATION,
                result.rejectionReason());
        assertEquals(SecurityEventType.TRAFFIC_ANOMALY,
                result.eventType());
        assertEquals(1, monitor.getEventCount());
    }

    @Test
    void rejectedMessageDoesNotBlockTheNextValidOne()
            throws GeneralSecurityException {

        SecureMessage first = sender.encrypt("one");
        SecureMessage second = sender.encrypt("two");

        receiver.receive(
                ProtocolTestSupport.tamperAuthenticationTag(first));

        // The sequence number must not advance on a rejection.
        assertTrue(receiver.receive(first).accepted());
        assertTrue(receiver.receive(second).accepted());
        assertEquals(1, monitor.getEventCount());
    }

    @Test
    void repeatedTamperingEscalatesToCriticalAndRecommendsRatchet()
            throws GeneralSecurityException {

        ReceiveResult last = null;

        for (int i = 0; i < 6; i++) {
            // Each attempt comes from a fresh sender so it carries the
            // sequence number the receiver still expects. Otherwise
            // later attempts would be rejected as out-of-order first.
            SecureMessage tampered = ProtocolTestSupport
                    .tamperAuthenticationTag(
                            createService(SESSION_ID).encrypt("m" + i));

            last = receiver.receive(tampered);
        }

        assertEquals(6, monitor.getEventCount());
        assertEquals(SecurityState.CRITICAL, monitor.getCurrentState());
        assertEquals(RatchetDecision.CRITICAL_RISK,
                last.ratchetDecision());
    }
}
