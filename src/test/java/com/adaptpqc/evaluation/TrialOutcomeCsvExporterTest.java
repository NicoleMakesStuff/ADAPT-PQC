package com.adaptpqc.evaluation;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TrialOutcomeCsvExporterTest {

    @TempDir
    Path tempDir;

    @Test
    void writesHeaderAndOneRowPerTrial() throws IOException {
        Path file = tempDir.resolve("nested").resolve("out.csv");

        TrialOutcomeCsvExporter.export(List.of(
                new TrialOutcome("a-1", false, false, 100, false, false),
                new TrialOutcome("b-2", true, true, 250, true, false)
        ), file);

        List<String> lines = Files.readAllLines(file);

        assertEquals(3, lines.size());
        assertTrue(lines.get(0).startsWith("trial_id,attack_present"));
        assertEquals("\"a-1\",false,false,100,false,false", lines.get(1));
        assertEquals("\"b-2\",true,true,250,true,false", lines.get(2));
    }

    @Test
    void escapesQuotesInTrialId() throws IOException {
        Path file = tempDir.resolve("quotes.csv");

        TrialOutcomeCsvExporter.export(List.of(
                new TrialOutcome("say \"hi\"", false, false, 1, false, false)
        ), file);

        assertEquals("\"say \"\"hi\"\"\",false,false,1,false,false",
                Files.readAllLines(file).get(1));
    }

    @Test
    void rejectsEmptyTrialListAndMissingPath() {
        Path file = tempDir.resolve("x.csv");

        assertThrows(IllegalArgumentException.class,
                () -> TrialOutcomeCsvExporter.export(List.of(), file));
        assertThrows(IllegalArgumentException.class,
                () -> TrialOutcomeCsvExporter.export(
                        List.of(new TrialOutcome(
                                "t", false, false, 0, false, false)),
                        null));
    }
}
