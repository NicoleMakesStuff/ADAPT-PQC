
package com.adaptpqc.ratchet;

import java.time.Duration;
import java.time.Instant;

import com.adaptpqc.security.SecurityState;
import com.adaptpqc.session.SessionState;

public class RatchetController {

    private static final long NORMAL_MESSAGE_LIMIT = 100;
    private static final long ELEVATED_MESSAGE_LIMIT = 25;

    private static final Duration NORMAL_KEY_AGE =
            Duration.ofMinutes(30);

    private static final Duration ELEVATED_KEY_AGE =
            Duration.ofMinutes(5);

    private static final Duration COOLDOWN =
            Duration.ofSeconds(30);

    /**
     * Evaluates whether the session should request a ratchet.
     *
     * This method makes a decision only. It does not generate
     * keys, modify session keys, or perform ML-KEM operations.
     */
    public RatchetDecision evaluate(SessionState session) {
        return evaluate(session, Instant.now());
    }

    /**
     * Time-injectable overload for deterministic testing.
     */
    public RatchetDecision evaluate(
            SessionState session,
            Instant now) {

        if (session == null || now == null) {
            throw new IllegalArgumentException(
                    "Session and evaluation time cannot be null."
            );
        }

        if (now.isBefore(session.getKeyCreatedAt())) {
            throw new IllegalArgumentException(
                    "Evaluation time cannot precede key creation."
            );
        }

        SecurityState state = session.getSecurityState();

        // Critical security state takes priority over cooldown.
        if (state == SecurityState.CRITICAL) {
            return RatchetDecision.CRITICAL_RISK;
        }

        // Avoid repeatedly requesting ratchets.
        Duration sinceLastRatchet =
                Duration.between(
                        session.getLastRatchetAt(),
                        now
                );

        if (sinceLastRatchet.compareTo(COOLDOWN) < 0) {
            return RatchetDecision.NO_RATCHET;
        }

        long messageLimit;
        Duration keyAgeLimit;

        if (state == SecurityState.ELEVATED) {
            messageLimit = ELEVATED_MESSAGE_LIMIT;
            keyAgeLimit = ELEVATED_KEY_AGE;
        } else {
            messageLimit = NORMAL_MESSAGE_LIMIT;
            keyAgeLimit = NORMAL_KEY_AGE;
        }

        // Prefer a message-trigger explanation if both apply.
        if (session.getMessageCount() >= messageLimit) {
            return RatchetDecision.MESSAGE_THRESHOLD;
        }

        Duration keyAge =
                Duration.between(
                        session.getKeyCreatedAt(),
                        now
                );

        if (keyAge.compareTo(keyAgeLimit) >= 0) {
            return RatchetDecision.KEY_AGE_THRESHOLD;
        }

        if (state == SecurityState.ELEVATED) {
            return RatchetDecision.ELEVATED_RISK;
        }

        return RatchetDecision.NO_RATCHET;
    }
}
