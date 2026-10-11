
package com.adaptpqc.evaluation;

import java.util.List;

public final class MetricsCalculator {

    private MetricsCalculator() {
    }

    public static EvaluationMetrics calculate(
            List<TrialOutcome> trials) {

        if (trials == null || trials.isEmpty()) {
            throw new IllegalArgumentException(
                    "At least one trial is required");
        }

        int tp = 0;
        int fp = 0;
        int tn = 0;
        int fn = 0;

        long latencySum = 0;
        int detectedAttackCount = 0;

        int ratchetRecommendations = 0;
        int ratchetsExecuted = 0;

        for (TrialOutcome trial : trials) {
            if (trial == null) {
                throw new IllegalArgumentException(
                        "Trials cannot contain null");
            }

            if (trial.attackPresent()) {
                if (trial.detected()) {
                    tp++;
                    latencySum = Math.addExact(
                            latencySum,
                            trial.detectionLatencyNanos());
                    detectedAttackCount++;
                } else {
                    fn++;
                }
            } else {
                if (trial.detected()) {
                    fp++;
                } else {
                    tn++;
                }
            }

            if (trial.ratchetRecommended()) {
                ratchetRecommendations++;
            }

            if (trial.ratchetExecuted()) {
                ratchetsExecuted++;
            }
        }

        double detectionRate = ratio(tp, tp + fn);
        double falsePositiveRate = ratio(fp, fp + tn);
        double precision = ratio(tp, tp + fp);

        double recall = detectionRate;
        double f1 = (precision + recall == 0.0)
                ? 0.0
                : 2.0 * precision * recall
                        / (precision + recall);

        double averageLatencyMs = detectedAttackCount == 0
                ? 0.0
                : (latencySum / (double) detectedAttackCount)
                        / 1_000_000.0;

        return new EvaluationMetrics(
                tp, fp, tn, fn,
                detectionRate,
                falsePositiveRate,
                precision,
                f1,
                averageLatencyMs,
                ratchetRecommendations,
                ratchetsExecuted);
    }

    private static double ratio(int numerator, int denominator) {
        return denominator == 0
                ? 0.0
                : numerator / (double) denominator;
    }
}
