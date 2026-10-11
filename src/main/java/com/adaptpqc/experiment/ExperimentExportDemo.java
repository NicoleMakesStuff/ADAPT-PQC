
package com.adaptpqc.experiment;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public class ExperimentExportDemo {

    public static void main(String[] args) throws IOException {
        // Temporary empty export to verify that CSV writing works.
        List<AttackExperimentRecord> records = List.of();

        CsvExperimentExporter.export(
                records,
                Path.of("results", "attack-experiment-results.csv")
        );

        System.out.println("CSV exported successfully.");
    }
}
