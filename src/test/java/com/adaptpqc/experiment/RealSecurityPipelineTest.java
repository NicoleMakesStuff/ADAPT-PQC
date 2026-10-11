
package com.adaptpqc.experiment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.adaptpqc.attack.AttackSimulator;
import com.adaptpqc.attack.AttackType;
import com.adaptpqc.security.SecurityState;

class RealSecurityPipelineTest {

    @Test
    void attackEventUpdatesRealRiskEngine() {
        RealSecurityPipeline pipeline = new RealSecurityPipeline();

        double riskBefore = pipeline.currentRiskScore();

        AttackExperimentRunner runner =
                new AttackExperimentRunner(
                        new AttackSimulator(), pipeline);

        AttackExperimentRecord result =
                runner.runOne(AttackType.CIPHERTEXT_TAMPERING);

        assertEquals(1, pipeline.eventCount());
        assertTrue(result.riskAfter() > riskBefore);
        assertEquals(
                pipeline.currentSecurityState(),
                result.stateAfter());
    }

    
    @Test
    void repeatedHighSeverityEventsCanEscalateSecurityState() {
        RealSecurityPipeline pipeline = new RealSecurityPipeline();
        AttackSimulator simulator = new AttackSimulator();

        for (int i = 0; i < 6; i++) {
            pipeline.process(
                    simulator.simulate(AttackType.CIPHERTEXT_TAMPERING));
        }

        assertEquals(SecurityState.CRITICAL,
                pipeline.sessionState().getSecurityState());

        assertEquals("CRITICAL_RISK",
                pipeline.evaluateRatchetDecision());
    }

    @Test
    void normalSessionInitiallyDoesNotRequireRatchet() {
        RealSecurityPipeline pipeline = new RealSecurityPipeline();

        assertEquals("NO_RATCHET",
                pipeline.evaluateRatchetDecision());
    }
}
