
package com.adaptpqc.experiment;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import com.adaptpqc.attack.AttackSimulator;

public final class AttackExperimentMain {

    private AttackExperimentMain() {
    }

    public static void main(String[] args) throws IOException {
        RealSecurityPipeline pipeline = new RealSecurityPipeline();

        AttackExperimentRunner runner =
                new AttackExperimentRunner(
                        new AttackSimulator(), pipeline);

        List<AttackExperimentRecord> results = runner.runAll();

        Path output = Path.of(
                "results", "attack-experiment-results.csv");

        CsvExperimentExporter.export(results, output);

        System.out.println("Experiment completed.");
        System.out.println("Events processed: " + pipeline.eventCount());
        System.out.println("Final risk score: " + pipeline.currentRiskScore());
        System.out.println("Final security state: "
                + pipeline.currentSecurityState());
        System.out.println("Final ratchet decision: "
                + pipeline.evaluateRatchetDecision());
        System.out.println("CSV saved to: "
                + output.toAbsolutePath());
    }
}
