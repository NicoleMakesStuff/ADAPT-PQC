
package com.adaptpqc.security;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.adaptpqc.session.SessionState;

class SecurityMonitorTest {

    @Test
    void newMonitorShouldStartWithNoEvents() {
        SessionState session = new SessionState();
        SecurityMonitor monitor = new SecurityMonitor(session);

        assertEquals(0, monitor.getEventCount());
        assertEquals(0.0, monitor.getCurrentRisk());
        assertEquals(
                SecurityState.NORMAL,
                monitor.getCurrentState()
        );
    }

    @Test
    void recordingEventShouldUpdateRiskAndState() {
        SessionState session = new SessionState();
        SecurityMonitor monitor = new SecurityMonitor(session);

        SecurityEvent event = new SecurityEvent(
                SecurityEventType.TRAFFIC_ANOMALY,
                0.80
        );

        monitor.recordEvent(event);

        // Initial risk is zero:
        // 0.7 * 0.0 + 0.3 * 0.8 = 0.24
        assertEquals(0.24, monitor.getCurrentRisk(), 0.0001);
        assertEquals(
                SecurityState.NORMAL,
                monitor.getCurrentState()
        );
        assertEquals(1, monitor.getEventCount());
    }

    @Test
    void repeatedSevereEventsShouldRaiseRisk() {
        SessionState session = new SessionState();
        SecurityMonitor monitor = new SecurityMonitor(session);

        for (int i = 0; i < 10; i++) {
            monitor.recordEvent(
                    new SecurityEvent(
                            SecurityEventType.CIPHERTEXT_TAMPERING,
                            1.0
                    )
            );
        }

        assertTrue(monitor.getCurrentRisk() >= 0.70);
        assertEquals(
                SecurityState.CRITICAL,
                monitor.getCurrentState()
        );
        assertEquals(10, monitor.getEventCount());
    }

    @Test
    void decayShouldUpdateSessionRisk() {
        SessionState session = new SessionState();
        SecurityMonitor monitor = new SecurityMonitor(session);

        session.setRiskScore(0.80);
        session.setSecurityState(SecurityState.CRITICAL);

        monitor.decayRisk();

        assertEquals(0.72, monitor.getCurrentRisk(), 0.0001);
        assertEquals(
                SecurityState.CRITICAL,
                monitor.getCurrentState()
        );
    }

    @Test
    void eventHistoryShouldNotBeModifiable() {
        SessionState session = new SessionState();
        SecurityMonitor monitor = new SecurityMonitor(session);

        monitor.recordEvent(
                new SecurityEvent(
                        SecurityEventType.REPLAY_ATTEMPT,
                        0.70
                )
        );

        List<SecurityEvent> events = monitor.getEvents();

        assertEquals(1, events.size());

        assertThrows(
                UnsupportedOperationException.class,
                () -> events.clear()
        );
    }

    @Test
    void nullEventShouldBeRejected() {
        SecurityMonitor monitor =
                new SecurityMonitor(new SessionState());

        assertThrows(
                IllegalArgumentException.class,
                () -> monitor.recordEvent(null)
        );
    }
}
