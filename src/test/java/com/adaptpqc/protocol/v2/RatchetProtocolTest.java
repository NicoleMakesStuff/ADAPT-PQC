package com.adaptpqc.protocol.v2;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class RatchetProtocolTest {
    private static final byte[] INITIAL_SECRET =
            "test-only-shared-secret-do-not-use-in-production"
                    .getBytes(StandardCharsets.UTF_8);
    private static final byte[] INITIAL_SALT = new byte[32];

    private record Pair(ProtocolSession alice, ProtocolSession bob,
                        RatchetProtocol.Responder responder, KeyPair kemKeys) {}

    private Pair pair() throws Exception {
        KeyPair keys = RatchetProtocol.generateMlKemKeyPair();
        ProtocolSession alice = new ProtocolSession(INITIAL_SECRET, INITIAL_SALT);
        ProtocolSession bob = new ProtocolSession(INITIAL_SECRET, INITIAL_SALT);
        return new Pair(alice, bob,
                new RatchetProtocol.Responder(bob, keys.getPrivate(), 100), keys);
    }

    @Test
    void successfulExchangeAllowsNewKeyCommunication() throws Exception {
        Pair p = pair();
        RatchetProtocol.Initiator initiator =
                RatchetProtocol.begin(p.alice(), p.kemKeys().getPublic());

        RatchetConfirmation confirmation =
                p.responder().receiveOffer(initiator.offer());
        RatchetFinalAck ack = initiator.acceptConfirmation(confirmation);
        p.responder().receiveFinalAck(ack);

        assertEquals(1, p.alice().generation());
        assertEquals(1, p.bob().generation());

        var encrypted = p.alice().encrypt("message after ratchet");
        assertEquals("message after ratchet",
                p.bob().decrypt(encrypted, p.alice().generation()));

        assertThrows(GeneralSecurityException.class,
                () -> p.bob().decrypt(encrypted, 0));
    }

    @Test
    void modifiedEncapsulationIsRejectedAndActiveGenerationUnchanged() throws Exception {
        Pair p = pair();
        RatchetProtocol.Initiator initiator =
                RatchetProtocol.begin(p.alice(), p.kemKeys().getPublic());
        RatchetOfferMessage original = initiator.offer();
        byte[] modified = original.encapsulation();
        modified[0] ^= 1;
        RatchetOfferMessage tampered = original.withEncapsulation(modified);

        assertThrows(GeneralSecurityException.class,
                () -> p.responder().receiveOffer(tampered));
        assertEquals(0, p.bob().generation());
        assertFalse(p.bob().hasPendingKeys());
    }

    @Test
    void modifiedSaltIsRejected() throws Exception {
        Pair p = pair();
        RatchetProtocol.Initiator initiator =
                RatchetProtocol.begin(p.alice(), p.kemKeys().getPublic());
        byte[] modified = initiator.offer().salt();
        modified[0] ^= 1;

        assertThrows(GeneralSecurityException.class,
                () -> p.responder().receiveOffer(initiator.offer().withSalt(modified)));
        assertEquals(0, p.bob().generation());
    }

    @Test
    void invalidAuthenticationTagIsRejectedWithoutKeyChange() throws Exception {
        Pair p = pair();
        RatchetProtocol.Initiator initiator =
                RatchetProtocol.begin(p.alice(), p.kemKeys().getPublic());
        byte[] badTag = initiator.offer().authenticationTag();
        badTag[0] ^= 1;

        assertThrows(GeneralSecurityException.class,
                () -> p.responder().receiveOffer(initiator.offer().withTag(badTag)));
        assertEquals(0, p.bob().generation());
        assertFalse(p.bob().hasPendingKeys());
    }

    @Test
    void duplicateOfferIsRejected() throws Exception {
        Pair p = pair();
        RatchetProtocol.Initiator initiator =
                RatchetProtocol.begin(p.alice(), p.kemKeys().getPublic());
        RatchetOfferMessage offer = initiator.offer();

        p.responder().receiveOffer(offer);
        p.responder().abort();

        // The same responder keeps the replay cache after aborting the pending
        // exchange, so the exact same offer ID is rejected on retry.
        assertThrows(GeneralSecurityException.class,
                () -> p.responder().receiveOffer(offer));
    }

    
        @Test
        void staleAndSkippedGenerationsAreRejected() throws Exception {
        Pair p = pair();

        RatchetProtocol.Initiator initiator =
                RatchetProtocol.begin(
                        p.alice(),
                        p.kemKeys().getPublic());

        RatchetOfferMessage valid = initiator.offer();

        // Generation zero is invalid at construction time.
        assertThrows(
                IllegalArgumentException.class,
                () -> new RatchetOfferMessage(
                        UUID.randomUUID(),
                        0,
                        valid.encapsulation(),
                        valid.salt(),
                        valid.authenticationTag()));

        // A skipped generation must be rejected by the responder.
        RatchetOfferMessage skipped = new RatchetOfferMessage(
                valid.offerId(),
                2,
                valid.encapsulation(),
                valid.salt(),
                valid.authenticationTag());

        assertThrows(
                GeneralSecurityException.class,
                () -> p.responder().receiveOffer(skipped));

        // The rejected offer must not alter the active session.
        assertEquals(0, p.bob().generation());
        assertFalse(p.bob().hasPendingKeys());

        // The original valid offer should still be processable.
        assertDoesNotThrow(
                () -> p.responder().receiveOffer(valid));
        }

    @Test
    void confirmationForAnotherOfferIsRejected() throws Exception {
        Pair p = pair();
        RatchetProtocol.Initiator initiator =
                RatchetProtocol.begin(p.alice(), p.kemKeys().getPublic());
        RatchetConfirmation wrong = new RatchetConfirmation(
                UUID.randomUUID(), 1, new byte[]{1, 2, 3});

        assertThrows(GeneralSecurityException.class,
                () -> initiator.acceptConfirmation(wrong));
        assertEquals(0, p.alice().generation());
        initiator.abort();
    }

    @Test
    void invalidConfirmationTagDoesNotCommitInitiatorKeys() throws Exception {
        Pair p = pair();
        RatchetProtocol.Initiator initiator =
                RatchetProtocol.begin(p.alice(), p.kemKeys().getPublic());
        RatchetConfirmation confirmation =
                p.responder().receiveOffer(initiator.offer());
        byte[] badTag = confirmation.authenticationTag();
        badTag[0] ^= 1;

        assertThrows(GeneralSecurityException.class,
                () -> initiator.acceptConfirmation(confirmation.withTag(badTag)));
        assertEquals(0, p.alice().generation());
        assertFalse(p.alice().hasPendingKeys());
    }

    @Test
    void abortBeforeConfirmationLeavesActiveGenerationUnchanged() throws Exception {
        Pair p = pair();
        RatchetProtocol.Initiator initiator =
                RatchetProtocol.begin(p.alice(), p.kemKeys().getPublic());
        initiator.abort();

        assertEquals(0, p.alice().generation());
        assertFalse(p.alice().hasPendingKeys());
        assertEquals("old-key-message",
                p.alice().decrypt(p.bob().encrypt("old-key-message"), 0));
    }

    @Test
    void invalidFinalAckDoesNotCommitResponderKeys() throws Exception {
        Pair p = pair();
        RatchetProtocol.Initiator initiator =
                RatchetProtocol.begin(p.alice(), p.kemKeys().getPublic());
        p.responder().receiveOffer(initiator.offer());
        RatchetFinalAck badAck = new RatchetFinalAck(
                initiator.offer().offerId(), 1, new byte[]{1, 2, 3});

        assertThrows(GeneralSecurityException.class,
                () -> p.responder().receiveFinalAck(badAck));
        assertEquals(0, p.bob().generation());
        assertFalse(p.bob().hasPendingKeys());
    }

    @Test
    void replayGuardRejectsDuplicateAndBoundsMemory() {
        ReplayGuard guard = new ReplayGuard(2);
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        UUID third = UUID.randomUUID();

        assertTrue(guard.accept(first));
        assertFalse(guard.accept(first));
        assertTrue(guard.accept(second));
        assertTrue(guard.accept(third));
        assertEquals(2, guard.size());
    }
}
