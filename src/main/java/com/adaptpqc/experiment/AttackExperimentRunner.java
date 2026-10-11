
package com.adaptpqc.experiment;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import com.adaptpqc.attack.AttackResult;
import com.adaptpqc.attack.AttackSimulator;
import com.adaptpqc.attack.AttackType;

public final class AttackExperimentRunner {

    /**
     * Adapter for the existing security-monitoring and ratchet pipeline.
     * Implement this using SecurityMonitor, SessionState, and
     * RatchetController once their exact APIs are confirmed.
     */
    public interface SecurityPipeline {
        double currentRiskScore();

        String currentSecurityState();

        String evaluateRatchetDecision();

        /**
         * Processes the generated security event.
         *
         * This is not, by itself, proof that a real attack was detected.
         * The current experiment records event processing separately from
         * any independently validated attack-detection result.
         */
        boolean process(AttackResult attack);
    }

    private final AttackSimulator simulator;
    private final SecurityPipeline pipeline;
    private final List<AttackExperimentRecord> records =
            new ArrayList<>();

    public AttackExperimentRunner(
            AttackSimulator simulator,
            SecurityPipeline pipeline) {
        this.simulator = Objects.requireNonNull(simulator);
        this.pipeline = Objects.requireNonNull(pipeline);
    }

    public synchronized AttackExperimentRecord runOne(AttackType type) {
        AttackResult attack = simulator.simulate(type);

        double riskBefore = pipeline.currentRiskScore();
        String stateBefore = pipeline.currentSecurityState();

        long start = System.nanoTime();

        boolean detected = pipeline.process(attack);

        String decision = pipeline.evaluateRatchetDecision();
        long elapsed = System.nanoTime() - start;

        double riskAfter = pipeline.currentRiskScore();
        String stateAfter = pipeline.currentSecurityState();

        AttackExperimentRecord record = new AttackExperimentRecord(
                attack.attackType(),
                attack.simulatedSeverity(),
                riskBefore,
                riskAfter,
                stateBefore,
                stateAfter,
                decision,
                attack.detectionExpected(),
                detected,
                elapsed
        );

        records.add(record);
        return record;
    }

    public synchronized List<AttackExperimentRecord> runAll() {
        for (AttackType type : AttackType.values()) {
            runOne(type);
        }

        return List.copyOf(records);
    }

    public synchronized List<AttackExperimentRecord> records() {
        return List.copyOf(records);
    }
}
