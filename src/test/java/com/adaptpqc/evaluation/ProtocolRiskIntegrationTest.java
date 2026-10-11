package com.adaptpqc.evaluation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.adaptpqc.ratchet.RatchetController;
import com.adaptpqc.ratchet.RatchetDecision;
import com.adaptpqc.security.SecurityEvent;
import com.adaptpqc.security.SecurityEventType;
import com.adaptpqc.security.SecurityMonitor;
import com.adaptpqc.security.SecurityState;
import com.adaptpqc.session.SessionState;

class ProtocolRiskIntegrationTest {

    @Test
    void tamperingEventsShouldIncreaseRisk() {
        SessionState session = new SessionState();
        SecurityMonitor monitor = new SecurityMonitor(session);

        double initialRisk = monitor.getCurrentRisk();

        monitor.recordEvent(new SecurityEvent(
                SecurityEventType.CIPHERTEXT_TAMPERING,
                0.90
        ));

        assertTrue(monitor.getCurrentRisk() > initialRisk);
        assertEquals(1, monitor.getEventCount());
    }

    @Test
    void repeatedSevereEventsShouldEscalateSecurityState() {
        SessionState session = new SessionState();
        SecurityMonitor monitor = new SecurityMonitor(session);

        for (int i = 0; i < 6; i++) {
            monitor.recordEvent(new SecurityEvent(
                    SecurityEventType.CIPHERTEXT_TAMPERING,
                    0.90
            ));
        }

        assertEquals(
                SecurityState.CRITICAL,
                monitor.getCurrentState()
        );
    }

    @Test
    void criticalRiskShouldRecommendImmediateRatchet() {
        SessionState session = new SessionState();
        SecurityMonitor monitor = new SecurityMonitor(session);

        monitor.recordEvent(new SecurityEvent(
                SecurityEventType.CIPHERTEXT_TAMPERING,
                0.90
        ));

        for (int i = 0; i < 5; i++) {
            monitor.recordEvent(new SecurityEvent(
                    SecurityEventType.CIPHERTEXT_TAMPERING,
                    0.90
            ));
        }

        RatchetController controller = new RatchetController();

        assertEquals(
                RatchetDecision.CRITICAL_RISK,
                controller.evaluate(session)
        );
    }

    @Test
    void normalSessionShouldNotImmediatelyRequestRatchet() {
        SessionState session = new SessionState();

        RatchetController controller = new RatchetController();

        assertEquals(
                RatchetDecision.NO_RATCHET,
                controller.evaluate(session)
        );
    }
}
