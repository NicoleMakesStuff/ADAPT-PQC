
package com.adaptpqc.evaluation;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.adaptpqc.protocol.v2.ProtocolSession;
import com.adaptpqc.protocol.v2.ProtocolTestSupport;
import com.adaptpqc.protocol.v2.SecureMessage;
import com.adaptpqc.protocol.v2.SecureMessageService;

public final class ProtocolEvaluationRunner {

    private static final byte[] SECRET = new byte[32];
    private static final byte[] SALT = new byte[32];

    private static final UUID SESSION_ID =
            UUID.fromString("12345678-1234-1234-1234-123456789012");

    private ProtocolEvaluationRunner() {
    }

    private static SecureMessageService createService()
            throws GeneralSecurityException {

        ProtocolSession session =
                new ProtocolSession(SECRET.clone(), SALT.clone());

        return new SecureMessageService(SESSION_ID, session);
    }

    public static void main(String[] args)
            throws GeneralSecurityException, IOException {

        List<TrialOutcome> outcomes = new ArrayList<>();

        // Trial 1: A legitimate message should be accepted.
        SecureMessageService sender = createService();
        SecureMessageService receiver = createService();

        SecureMessage legitimate = sender.encrypt("Legitimate message");

        long start = System.nanoTime();
        boolean accepted = false;

        try {
            receiver.decrypt(legitimate);
            accepted = true;
        } catch (GeneralSecurityException ignored) {
            // Record the observed rejection.
        }

        long latency = System.nanoTime() - start;

        outcomes.add(new TrialOutcome(
                "legitimate-001",
                false,
                !accepted,
                latency,
                false,
                false
        ));

        // Trial 2: A replay should be rejected.
        sender = createService();
        receiver = createService();

        SecureMessage original = sender.encrypt("Replay test");

        // Establish that the original message is accepted.
        receiver.decrypt(original);

        start = System.nanoTime();
        boolean replayRejected = false;

        try {
            receiver.decrypt(original);
        } catch (GeneralSecurityException expected) {
            replayRejected = true;
        }

        latency = System.nanoTime() - start;

        outcomes.add(new TrialOutcome(
                "replay-001",
                true,
                replayRejected,
                latency,
                false,
                false
        ));

        // Trial 3: A modified authentication tag should be rejected.
        sender = createService();
        receiver = createService();

        SecureMessage originalForTampering =
                sender.encrypt("Tampering test");

        SecureMessage tampered =
        ProtocolTestSupport.tamperAuthenticationTag(
                originalForTampering
        );

        start = System.nanoTime();
        boolean tamperingRejected = false;

        try {
            receiver.decrypt(tampered);
        } catch (GeneralSecurityException expected) {
            tamperingRejected = true;
        }

        latency = System.nanoTime() - start;

        outcomes.add(new TrialOutcome(
                "tampering-001",
                true,
                tamperingRejected,
                latency,
                false,
                false
        ));

        // Print raw trial outcomes.
        System.out.println("=== ADAPT-PQC Protocol Evaluation ===");

        for (TrialOutcome outcome : outcomes) {
            System.out.printf(
                    "%s | attackPresent=%s | detected=%s"
                            + " | latencyNs=%d%n",
                    outcome.trialId(),
                    outcome.attackPresent(),
                    outcome.detected(),
                    outcome.detectionLatencyNanos()
            );
        }

        System.out.println("Total trials: " + outcomes.size());
        System.out.println(
                "Attack trials: "
                        + outcomes.stream()
                        .filter(TrialOutcome::attackPresent)
                        .count()
        );

        System.out.println(
                "Detected attacks: "
                        + outcomes.stream()
                        .filter(o -> o.attackPresent() && o.detected())
                        .count()
        );

        System.out.println(
                "Legitimate-message false positives: "
                        + outcomes.stream()
                        .filter(o -> !o.attackPresent() && o.detected())
                        .count()
        );

        // Calculate aggregate evaluation metrics.
        EvaluationMetrics metrics =
                MetricsCalculator.calculate(outcomes);

        System.out.println();
        System.out.println("=== Evaluation Metrics ===");

        System.out.println(
                "True positives: "
                        + metrics.truePositives());

        System.out.println(
                "False positives: "
                        + metrics.falsePositives());

        System.out.println(
                "True negatives: "
                        + metrics.trueNegatives());

        System.out.println(
                "False negatives: "
                        + metrics.falseNegatives());

        System.out.printf(
                "Detection rate: %.2f%%%n",
                metrics.detectionRate() * 100.0);

        System.out.printf(
                "False-positive rate: %.2f%%%n",
                metrics.falsePositiveRate() * 100.0);

        System.out.printf(
                "Precision: %.2f%%%n",
                metrics.precision() * 100.0);

        System.out.printf(
                "F1 score: %.4f%n",
                metrics.f1Score());

        System.out.printf(
                "Average detection latency: %.3f ms%n",
                metrics.averageDetectionLatencyMs());

        System.out.println(
                "Ratchet recommendations: "
                        + metrics.ratchetRecommendations());

        System.out.println(
                "Ratchets executed: "
                        + metrics.ratchetsExecuted());

        Path csvPath = Path.of(
                "results",
                "protocol-evaluation.csv"
        );

        TrialOutcomeCsvExporter.export(outcomes, csvPath);

        System.out.println(
                "Trial results saved to: "
                        + csvPath.toAbsolutePath());
    }
}
