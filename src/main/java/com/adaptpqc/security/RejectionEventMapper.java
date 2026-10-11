package com.adaptpqc.security;

import com.adaptpqc.protocol.v2.ProtocolRejectionReason;

/**
 * Maps a protocol rejection to a security event.
 *
 * Severities match the values used by AttackSimulator so the
 * simulated and observed experiments stay comparable.
 */
public final class RejectionEventMapper {

    private static final double REPLAY_SEVERITY = 0.70;
    private static final double TAMPERING_SEVERITY = 0.90;
    private static final double AUTH_FAILURE_SEVERITY = 0.75;
    private static final double ANOMALY_SEVERITY = 0.60;

    private RejectionEventMapper() {
    }

    public static SecurityEvent toEvent(
            ProtocolRejectionReason reason) {

        if (reason == null) {
            throw new IllegalArgumentException(
                    "Rejection reason is required");
        }

        return switch (reason) {

            // The sequence number was already used or is out of order.
            case REPLAY_OR_OUT_OF_ORDER -> new SecurityEvent(
                    SecurityEventType.REPLAY_ATTEMPT,
                    REPLAY_SEVERITY);

            // The MAC over the metadata and ciphertext did not verify,
            // so the message was altered or forged.
            case AUTHENTICATION_FAILED -> new SecurityEvent(
                    SecurityEventType.CIPHERTEXT_TAMPERING,
                    TAMPERING_SEVERITY);

            // The MAC passed but decryption still failed, or the
            // message claims a session that is not ours.
            case DECRYPTION_FAILED, WRONG_SESSION -> new SecurityEvent(
                    SecurityEventType.AUTHENTICATION_FAILURE,
                    AUTH_FAILURE_SEVERITY);

            // A stale generation or a null message can come from an
            // honest peer after a rotation, so it is only an anomaly.
            case WRONG_GENERATION, NULL_MESSAGE -> new SecurityEvent(
                    SecurityEventType.TRAFFIC_ANOMALY,
                    ANOMALY_SEVERITY);
        };
    }
}
