
package com.adaptpqc.experiment;

import com.adaptpqc.attack.AttackType;

public record AttackExperimentRecord(
        AttackType attackType,
        double severity,
        double riskBefore,
        double riskAfter,
        String stateBefore,
        String stateAfter,
        String ratchetDecision,
        boolean detectionExpected,
        boolean detected,
        long processingTimeNanos
) {
    public AttackExperimentRecord {
        if (attackType == null) {
            throw new IllegalArgumentException("Attack type is required");
        }

        if (!validRisk(riskBefore) || !validRisk(riskAfter)) {
            throw new IllegalArgumentException(
                    "Risk scores must be finite and between 0 and 1");
        }

        if (!Double.isFinite(severity)
                || severity < 0.0
                || severity > 1.0) {
            throw new IllegalArgumentException(
                    "Severity must be between 0 and 1");
        }

        if (stateBefore == null || stateAfter == null
                || ratchetDecision == null) {
            throw new IllegalArgumentException(
                    "State and decision values are required");
        }

        if (processingTimeNanos < 0) {
            throw new IllegalArgumentException(
                    "Processing time cannot be negative");
        }
    }

    private static boolean validRisk(double value) {
        return Double.isFinite(value)
                && value >= 0.0
                && value <= 1.0;
    }
}
