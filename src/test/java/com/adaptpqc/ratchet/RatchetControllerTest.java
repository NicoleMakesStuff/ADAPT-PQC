
package com.adaptpqc.ratchet;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

import com.adaptpqc.security.SecurityState;
import com.adaptpqc.session.SessionState;

class RatchetControllerTest {

    private final RatchetController controller =
            new RatchetController();

    @Test
    void normalSessionShouldNotRatchetImmediately() {
        SessionState session = new SessionState();

        assertEquals(
                RatchetDecision.NO_RATCHET,
                controller.evaluate(session)
        );
    }

    @Test
    void normalSessionShouldRatchetAtMessageThreshold() {
        SessionState session = new SessionState();

        for (int i = 0; i < 100; i++) {
            session.incrementMessageCount();
        }

        Instant now = session.getLastRatchetAt()
                .plusSeconds(31);

        assertEquals(
                RatchetDecision.MESSAGE_THRESHOLD,
                controller.evaluate(session, now)
        );
    }

    @Test
    void elevatedSessionShouldUseLowerMessageThreshold() {
        SessionState session = new SessionState();

        session.setSecurityState(SecurityState.ELEVATED);

        for (int i = 0; i < 25; i++) {
            session.incrementMessageCount();
        }

        Instant now = session.getLastRatchetAt()
                .plusSeconds(31);

        assertEquals(
                RatchetDecision.MESSAGE_THRESHOLD,
                controller.evaluate(session, now)
        );
    }

    @Test
    void criticalRiskShouldRequestImmediateRatchet() {
        SessionState session = new SessionState();

        session.setSecurityState(SecurityState.CRITICAL);

        // Even a recent ratchet must not suppress this request.
        assertEquals(
                RatchetDecision.CRITICAL_RISK,
                controller.evaluate(session)
        );
    }

    @Test
    void cooldownShouldSuppressNormalRatchetRequests() {
        SessionState session = new SessionState();

        for (int i = 0; i < 100; i++) {
            session.incrementMessageCount();
        }

        Instant now = session.getLastRatchetAt()
                .plusSeconds(10);

        assertEquals(
                RatchetDecision.NO_RATCHET,
                controller.evaluate(session, now)
        );
    }

    @Test
    void oldNormalKeyShouldRequestRatchet() {
        SessionState session = new SessionState();

        Instant now = session.getKeyCreatedAt()
                .plusSeconds(1800);

        assertEquals(
                RatchetDecision.KEY_AGE_THRESHOLD,
                controller.evaluate(session, now)
        );
    }

    @Test
    void oldElevatedKeyShouldRequestRatchet() {
        SessionState session = new SessionState();

        session.setSecurityState(SecurityState.ELEVATED);

        Instant now = session.getKeyCreatedAt()
                .plusSeconds(301);

        assertEquals(
                RatchetDecision.KEY_AGE_THRESHOLD,
                controller.evaluate(session, now)
        );
    }

    @Test
    void elevatedStateShouldRequestRatchetAfterCooldown() {
        SessionState session = new SessionState();

        session.setSecurityState(SecurityState.ELEVATED);

        Instant now = session.getLastRatchetAt()
                .plusSeconds(31);

        assertEquals(
                RatchetDecision.ELEVATED_RISK,
                controller.evaluate(session, now)
        );
    }

    @Test
    void nullSessionShouldBeRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> controller.evaluate(null)
        );
    }
}
