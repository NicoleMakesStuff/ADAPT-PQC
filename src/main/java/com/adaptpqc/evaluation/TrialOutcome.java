
package com.adaptpqc.evaluation;

public record TrialOutcome(
        String trialId,
        boolean attackPresent,
        boolean detected,
        long detectionLatencyNanos,
        boolean ratchetRecommended,
        boolean ratchetExecuted
) {
    public TrialOutcome {
        if (trialId == null || trialId.isBlank()) {
            throw new IllegalArgumentException(
                    "Trial ID is required");
        }

        if (detectionLatencyNanos < 0) {
            throw new IllegalArgumentException(
                    "Latency cannot be negative");
        }

        if (ratchetExecuted && !ratchetRecommended) {
            throw new IllegalArgumentException(
                    "An executed ratchet must have been recommended");
        }
    }
}
