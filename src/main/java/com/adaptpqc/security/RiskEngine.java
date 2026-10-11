
package com.adaptpqc.security;

public class RiskEngine {

    private static final double ALPHA = 0.70;
    private static final double DECAY_FACTOR = 0.90;

    private static final double ELEVATED_THRESHOLD = 0.30;
    private static final double CRITICAL_THRESHOLD = 0.70;

    /**
     * Updates the risk score using the previous risk score
     * and the severity of a new security event.
     *
     * R(t) = alpha * R(t-1) + (1-alpha) * eventSeverity
     *
     * @param currentRisk previous risk score in [0, 1]
     * @param event       new security event
     * @return updated risk score in [0, 1]
     */
    public double calculateRisk(
            double currentRisk,
            SecurityEvent event) {

        validateRisk(currentRisk);

        if (event == null) {
            throw new IllegalArgumentException(
                    "Security event cannot be null."
            );
        }

        double severity = event.getSeverity();

        validateRisk(severity);

        double newRisk =
                ALPHA * currentRisk
                + (1.0 - ALPHA) * severity;

        return clamp(newRisk);
    }

    /**
     * Determines the security state associated with a risk score.
     *
     * NORMAL:   risk < 0.30
     * ELEVATED: 0.30 <= risk < 0.70
     * CRITICAL: risk >= 0.70
     *
     * RECOVERY is managed separately by the session/state machine.
     *
     * @param riskScore risk score in [0, 1]
     * @return corresponding security state
     */
    public SecurityState determineState(double riskScore) {

        validateRisk(riskScore);

        if (riskScore >= CRITICAL_THRESHOLD) {
            return SecurityState.CRITICAL;
        }

        if (riskScore >= ELEVATED_THRESHOLD) {
            return SecurityState.ELEVATED;
        }

        return SecurityState.NORMAL;
    }

    /**
     * Reduces risk when no new security event occurs.
     *
     * This method represents one decay step, not a fixed
     * time interval. The caller determines when it is applied.
     *
     * @param currentRisk current risk score in [0, 1]
     * @return decayed risk score
     */
    public double decayRisk(double currentRisk) {

        validateRisk(currentRisk);

        return clamp(currentRisk * DECAY_FACTOR);
    }

    public double getElevatedThreshold() {
        return ELEVATED_THRESHOLD;
    }

    public double getCriticalThreshold() {
        return CRITICAL_THRESHOLD;
    }

    public double getAlpha() {
        return ALPHA;
    }

    public double getDecayFactor() {
        return DECAY_FACTOR;
    }

    private void validateRisk(double risk) {

        if (!Double.isFinite(risk)
                || risk < 0.0
                || risk > 1.0) {

            throw new IllegalArgumentException(
                    "Risk score must be finite and between 0 and 1."
            );
        }
    }

    private double clamp(double value) {
        return Math.max(0.0, Math.min(1.0, value));
    }
}
