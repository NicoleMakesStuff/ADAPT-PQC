
package com.adaptpqc.evaluation;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

class MetricsCalculatorTest {

    @Test
    void calculatesDetectionAndFalsePositiveRates() {
        List<TrialOutcome> trials = List.of(
                new TrialOutcome("A1", true, true,
                        2_000_000, true, false),
                new TrialOutcome("A2", true, false,
                        0, false, false),
                new TrialOutcome("L1", false, true,
                        1_000_000, false, false),
                new TrialOutcome("L2", false, false,
                        0, false, false)
        );

        EvaluationMetrics metrics =
                MetricsCalculator.calculate(trials);

        assertEquals(1, metrics.truePositives());
        assertEquals(1, metrics.falseNegatives());
        assertEquals(1, metrics.falsePositives());
        assertEquals(1, metrics.trueNegatives());

        assertEquals(0.5, metrics.detectionRate(), 0.0001);
        assertEquals(0.5, metrics.falsePositiveRate(), 0.0001);
        assertEquals(0.5, metrics.precision(), 0.0001);
        assertEquals(0.5, metrics.f1Score(), 0.0001);

        assertEquals(
                2.0,
                metrics.averageDetectionLatencyMs(),
                0.0001);
    }

    @Test
    void handlesPerfectDetection() {
        List<TrialOutcome> trials = List.of(
                new TrialOutcome("A1", true, true,
                        1_000_000, true, false),
                new TrialOutcome("L1", false, false,
                        0, false, false)
        );

        EvaluationMetrics metrics =
                MetricsCalculator.calculate(trials);

        assertEquals(1.0, metrics.detectionRate(), 0.0001);
        assertEquals(0.0, metrics.falsePositiveRate(), 0.0001);
        assertEquals(1.0, metrics.precision(), 0.0001);
        assertEquals(1.0, metrics.f1Score(), 0.0001);
    }

    @Test
    void rejectsEmptyTrialList() {
        assertThrows(
                IllegalArgumentException.class,
                () -> MetricsCalculator.calculate(List.of()));
    }

    @Test
    void rejectsNullTrialList() {
        assertThrows(
                IllegalArgumentException.class,
                () -> MetricsCalculator.calculate(null));
    }

    @Test
    void rejectsNegativeLatency() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new TrialOutcome(
                        "A1", true, true,
                        -1, false, false));
    }
}
