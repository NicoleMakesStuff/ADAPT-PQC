
package com.adaptpqc.experiment;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class CsvExperimentExporter {

    private CsvExperimentExporter() {
    }

    public static void export(
            List<AttackExperimentRecord> records,
            Path outputPath) throws IOException {

        if (records == null || outputPath == null) {
            throw new IllegalArgumentException(
                    "Records and output path are required");
        }

        Path parent = outputPath.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        try (BufferedWriter writer = Files.newBufferedWriter(
                outputPath, StandardCharsets.UTF_8)) {

            writer.write(
                    "attack_type,severity,risk_before,risk_after,"
                    + "state_before,state_after,ratchet_decision,"
                    + "detection_expected,detected,processing_time_ns");
            writer.newLine();

            for (AttackExperimentRecord record : records) {
                writer.write(String.join(",",
                        csv(record.attackType().name()),
                        Double.toString(record.severity()),
                        Double.toString(record.riskBefore()),
                        Double.toString(record.riskAfter()),
                        csv(record.stateBefore()),
                        csv(record.stateAfter()),
                        csv(record.ratchetDecision()),
                        Boolean.toString(record.detectionExpected()),
                        Boolean.toString(record.detected()),
                        Long.toString(record.processingTimeNanos())
                ));
                writer.newLine();
            }
        }
    }

    private static String csv(String value) {
        String escaped = value.replace("\"", "\"\"");
        return "\"" + escaped + "\"";
    }
}
