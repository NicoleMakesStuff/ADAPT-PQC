
package com.adaptpqc.attack;

import com.adaptpqc.security.SecurityEvent;
import com.adaptpqc.security.SecurityEventType;

public final class AttackSimulator {

    public AttackResult simulate(AttackType type) {
        if (type == null) {
            throw new IllegalArgumentException(
                    "Attack type must not be null");
        }

        SecurityEventType eventType;
        double severity;

        switch (type) {
            case REPLAY -> {
                eventType = SecurityEventType.REPLAY_ATTEMPT;
                severity = 0.70;
            }
            case CIPHERTEXT_TAMPERING -> {
                eventType = SecurityEventType.CIPHERTEXT_TAMPERING;
                severity = 0.90;
            }
            case INVALID_SIGNATURE -> {
                eventType = SecurityEventType.INVALID_SIGNATURE;
                severity = 0.85;
            }
            case AUTHENTICATION_FAILURE -> {
                eventType = SecurityEventType.AUTHENTICATION_FAILURE;
                severity = 0.75;
            }
            case TRAFFIC_ANOMALY -> {
                eventType = SecurityEventType.TRAFFIC_ANOMALY;
                severity = 0.60;
            }
            default -> throw new IllegalArgumentException(
                    "Unsupported attack type: " + type);
        }

        SecurityEvent event = new SecurityEvent(
                eventType,
                severity);

        return new AttackResult(
                type,
                event,
                severity,
                true);
    }
}
