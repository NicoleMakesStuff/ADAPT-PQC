package com.adaptpqc.evaluation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class TrialOutcomeCsvExporter {

    private TrialOutcomeCsvExporter() {
    }

    public static void export(
            List<TrialOutcome> outcomes,
            Path outputFile) throws IOException {

        if (outcomes == null || outcomes.isEmpty()) {
            throw new IllegalArgumentException(
                    "At least one trial is required");
        }

        if (outputFile == null) {
            throw new IllegalArgumentException(
                    "Output path is required");
        }

        Path parent = outputFile.toAbsolutePath().getParent();

        if (parent != null) {
            Files.createDirectories(parent);
        }

        StringBuilder csv = new StringBuilder();

        csv.append(
                "trial_id,attack_present,detected,"
                + "detection_latency_ns,"
                + "ratchet_recommended,ratchet_executed\n");

        for (TrialOutcome outcome : outcomes) {
            if (outcome == null) {
                throw new IllegalArgumentException(
                        "Trials cannot contain null");
            }

            csv.append(escape(outcome.trialId())).append(',')
                    .append(outcome.attackPresent()).append(',')
                    .append(outcome.detected()).append(',')
                    .append(outcome.detectionLatencyNanos()).append(',')
                    .append(outcome.ratchetRecommended()).append(',')
                    .append(outcome.ratchetExecuted())
                    .append('\n');
        }

        Files.writeString(
                outputFile,
                csv.toString(),
                StandardCharsets.UTF_8);
    }

    private static String escape(String value) {
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }
}
