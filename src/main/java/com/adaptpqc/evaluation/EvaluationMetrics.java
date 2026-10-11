
package com.adaptpqc.evaluation;

public record EvaluationMetrics(
        int truePositives,
        int falsePositives,
        int trueNegatives,
        int falseNegatives,
        double detectionRate,
        double falsePositiveRate,
        double precision,
        double f1Score,
        double averageDetectionLatencyMs,
        int ratchetRecommendations,
        int ratchetsExecuted
) {
}
