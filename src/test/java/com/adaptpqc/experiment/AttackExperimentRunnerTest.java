
package com.adaptpqc.experiment;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.adaptpqc.attack.AttackSimulator;
import com.adaptpqc.attack.AttackType;

class AttackExperimentRunnerTest {

    static final class FakePipeline
            implements AttackExperimentRunner.SecurityPipeline {

        private double risk = 0.10;
        private String state = "NORMAL";
        private String decision = "NO_RATCHET";

        @Override
        public double currentRiskScore() {
            return risk;
        }

        @Override
        public String currentSecurityState() {
            return state;
        }

        @Override
        public String evaluateRatchetDecision() {
            return decision;
        }

        @Override
        public boolean process(
                com.adaptpqc.attack.AttackResult attack) {
            risk = Math.min(1.0, risk + attack.simulatedSeverity() * 0.5);

            if (risk >= 0.70) {
                state = "CRITICAL";
                decision = "CRITICAL_RISK";
            } else if (risk >= 0.30) {
                state = "ELEVATED";
                decision = "ELEVATED_RISK";
            }

            // This fake pipeline's detection rule is deliberately
            // simple and is used only to test runner bookkeeping.
            return attack.simulatedSeverity() >= 0.60;
        }
    }

    @Test
    void recordsAttackAndPipelineResults() {
        AttackExperimentRunner runner =
                new AttackExperimentRunner(
                        new AttackSimulator(),
                        new FakePipeline());

        AttackExperimentRecord record =
                runner.runOne(AttackType.CIPHERTEXT_TAMPERING);

        assertEquals(
                AttackType.CIPHERTEXT_TAMPERING,
                record.attackType());

        assertTrue(record.detected());
        assertTrue(record.riskAfter() > record.riskBefore());
        assertTrue(record.processingTimeNanos() >= 0);
        assertEquals(1, runner.records().size());
    }

    @Test
    void runAllCoversEveryAttackType() {
        AttackExperimentRunner runner =
                new AttackExperimentRunner(
                        new AttackSimulator(),
                        new FakePipeline());

        List<AttackExperimentRecord> results = runner.runAll();

        assertEquals(
                AttackType.values().length,
                results.size());
    }

    @Test
    void returnedRecordsCannotModifyInternalList() {
        AttackExperimentRunner runner =
                new AttackExperimentRunner(
                        new AttackSimulator(),
                        new FakePipeline());

        runner.runOne(AttackType.REPLAY);

        List<AttackExperimentRecord> results = runner.records();

        assertThrows(
                UnsupportedOperationException.class,
                results::clear);
    }
}
