package com.adaptpqc.security;

import java.time.Instant;

public class SecurityEvent {

    private final SecurityEventType type;
    private final Instant timestamp;
    private final double severity;

    public SecurityEvent(
            SecurityEventType type,
            double severity) {

        if (type == null) {
            throw new IllegalArgumentException(
                    "Event type cannot be null."
            );
        }

        if (severity < 0.0 || severity > 1.0) {
            throw new IllegalArgumentException(
                    "Severity must be between 0.0 and 1.0."
            );
        }

        this.type = type;
        this.timestamp = Instant.now();
        this.severity = severity;
    }

    public SecurityEventType getType() {
        return type;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public double getSeverity() {
        return severity;
    }
}