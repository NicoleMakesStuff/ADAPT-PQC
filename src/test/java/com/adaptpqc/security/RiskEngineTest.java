
package com.adaptpqc.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class RiskEngineTest {

    private final RiskEngine engine = new RiskEngine();

    @Test
    void lowSeverityEventShouldProduceLowRisk() {

        SecurityEvent event = new SecurityEvent(
                SecurityEventType.MESSAGE_COUNT_THRESHOLD,
                0.10
        );

        double risk = engine.calculateRisk(0.0, event);

        assertEquals(0.03, risk, 0.0001);

        assertEquals(
                SecurityState.NORMAL,
                engine.determineState(risk)
        );
    }

    @Test
    void moderateEventShouldProduceElevatedRisk() {

        SecurityEvent event = new SecurityEvent(
                SecurityEventType.TRAFFIC_ANOMALY,
                0.80
        );

        double risk = engine.calculateRisk(0.30, event);

        // 0.70 * 0.30 + 0.30 * 0.80 = 0.45
        assertEquals(0.45, risk, 0.0001);

        assertEquals(
                SecurityState.ELEVATED,
                engine.determineState(risk)
        );
    }

    @Test
    void repeatedSevereEventsShouldReachCriticalRisk() {

        SecurityEvent event = new SecurityEvent(
                SecurityEventType.CIPHERTEXT_TAMPERING,
                1.0
        );

        double risk = 0.0;

        for (int i = 0; i < 10; i++) {
            risk = engine.calculateRisk(risk, event);
        }

        assertTrue(risk >= engine.getCriticalThreshold());

        assertEquals(
                SecurityState.CRITICAL,
                engine.determineState(risk)
        );
    }

    @Test
    void riskShouldDecay() {

        double initialRisk = 0.80;

        double decayedRisk = engine.decayRisk(initialRisk);

        assertEquals(0.72, decayedRisk, 0.0001);
        assertTrue(decayedRisk < initialRisk);
    }

    @Test
    void repeatedDecayShouldReduceRisk() {

        double risk = 0.80;

        for (int i = 0; i < 5; i++) {
            risk = engine.decayRisk(risk);
        }

        assertTrue(risk < 0.80);
        assertTrue(risk >= 0.0);
    }

    @Test
    void stateThresholdsShouldBeCorrect() {

        assertEquals(
                SecurityState.NORMAL,
                engine.determineState(0.0)
        );

        assertEquals(
                SecurityState.NORMAL,
                engine.determineState(0.2999)
        );

        assertEquals(
                SecurityState.ELEVATED,
                engine.determineState(0.30)
        );

        assertEquals(
                SecurityState.ELEVATED,
                engine.determineState(0.6999)
        );

        assertEquals(
                SecurityState.CRITICAL,
                engine.determineState(0.70)
        );

        assertEquals(
                SecurityState.CRITICAL,
                engine.determineState(1.0)
        );
    }

    @Test
    void nullEventShouldBeRejected() {

        assertThrows(
                IllegalArgumentException.class,
                () -> engine.calculateRisk(0.2, null)
        );
    }

    @Test
    void invalidRiskValuesShouldBeRejected() {

        assertThrows(
                IllegalArgumentException.class,
                () -> engine.determineState(1.5)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> engine.determineState(-0.1)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> engine.determineState(Double.NaN)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> engine.calculateRisk(-0.1,
                        new SecurityEvent(
                                SecurityEventType.TRAFFIC_ANOMALY,
                                0.5
                        ))
        );
    }

    @Test
    void invalidEventSeverityShouldBeRejected() {

        assertThrows(
                IllegalArgumentException.class,
                () -> new SecurityEvent(
                        SecurityEventType.TRAFFIC_ANOMALY,
                        1.5
                )
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new SecurityEvent(
                        SecurityEventType.TRAFFIC_ANOMALY,
                        -0.1
                )
        );
    }

    @Test
    void riskScoreShouldNeverExceedOne() {

        SecurityEvent event = new SecurityEvent(
                SecurityEventType.INVALID_SIGNATURE,
                1.0
        );

        double risk = 1.0;

        for (int i = 0; i < 20; i++) {
            risk = engine.calculateRisk(risk, event);

            assertTrue(risk <= 1.0);
            assertTrue(risk >= 0.0);
        }
    }
}
