
package com.adaptpqc.attack;

import com.adaptpqc.security.SecurityEvent;

public record AttackResult(
        AttackType attackType,
        SecurityEvent event,
        double simulatedSeverity,
        boolean detectionExpected
) {
    public AttackResult {
        if (attackType == null || event == null) {
            throw new IllegalArgumentException(
                    "Attack type and event are required");
        }

        if (!Double.isFinite(simulatedSeverity)
                || simulatedSeverity < 0.0
                || simulatedSeverity > 1.0) {
            throw new IllegalArgumentException(
                    "Severity must be between 0 and 1");
        }
    }
}
