
package com.adaptpqc.attack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.adaptpqc.security.SecurityEventType;

class AttackSimulatorTest {

    private final AttackSimulator simulator =
            new AttackSimulator();

    @Test
    void replayProducesReplayEvent() {
        AttackResult result =
                simulator.simulate(AttackType.REPLAY);

        assertEquals(
                SecurityEventType.REPLAY_ATTEMPT,
                result.event().getType());

        assertEquals(0.70, result.simulatedSeverity(), 0.0001);
        assertTrue(result.detectionExpected());
    }

    @Test
    void ciphertextTamperingProducesCorrectEvent() {
        AttackResult result =
                simulator.simulate(AttackType.CIPHERTEXT_TAMPERING);

        assertEquals(
                SecurityEventType.CIPHERTEXT_TAMPERING,
                result.event().getType());

        assertEquals(0.90, result.simulatedSeverity(), 0.0001);
    }

    @Test
    void invalidSignatureProducesCorrectEvent() {
        AttackResult result =
                simulator.simulate(AttackType.INVALID_SIGNATURE);

        assertEquals(
                SecurityEventType.INVALID_SIGNATURE,
                result.event().getType());
    }

    @Test
    void authenticationFailureProducesCorrectEvent() {
        AttackResult result =
                simulator.simulate(AttackType.AUTHENTICATION_FAILURE);

        assertEquals(
                SecurityEventType.AUTHENTICATION_FAILURE,
                result.event().getType());
    }

    @Test
    void trafficAnomalyProducesCorrectEvent() {
        AttackResult result =
                simulator.simulate(AttackType.TRAFFIC_ANOMALY);

        assertEquals(
                SecurityEventType.TRAFFIC_ANOMALY,
                result.event().getType());
    }

    @Test
    void nullAttackTypeIsRejected() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> simulator.simulate(null));

        assertEquals(
                "Attack type must not be null",
                exception.getMessage());
}
}
