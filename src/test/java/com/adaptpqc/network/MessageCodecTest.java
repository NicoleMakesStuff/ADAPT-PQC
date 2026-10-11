
package com.adaptpqc.network;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

class MessageCodecTest {

    @Test
    void roundTripFrame() throws IOException {
        byte[] original =
                "encrypted-payload".getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);

        MessageCodec.writeFrame(out, original);

        DataInputStream in = new DataInputStream(
                new ByteArrayInputStream(bytes.toByteArray())
        );

        assertArrayEquals(original, MessageCodec.readFrame(in));
    }

    @Test
    void rejectsEmptyFrame() {
        byte[] encodedLength = {0, 0, 0, 0};

        DataInputStream in = new DataInputStream(
                new ByteArrayInputStream(encodedLength)
        );

        assertThrows(
                IOException.class,
                () -> MessageCodec.readFrame(in)
        );
    }

    @Test
    void rejectsOversizedFrame() {
        int maxPlusOne = 1_048_577;

        byte[] encodedLength = {
                (byte) (maxPlusOne >>> 24),
                (byte) (maxPlusOne >>> 16),
                (byte) (maxPlusOne >>> 8),
                (byte) maxPlusOne
        };

        DataInputStream in = new DataInputStream(
                new ByteArrayInputStream(encodedLength)
        );

        assertThrows(
                IOException.class,
                () -> MessageCodec.readFrame(in)
        );
    }

    @Test
    void rejectsTruncatedFrame() {
        // Declares 5 bytes, but provides only 2.
        byte[] malformed = {0, 0, 0, 5, 10, 20};

        DataInputStream in = new DataInputStream(
                new ByteArrayInputStream(malformed)
        );

        assertThrows(
                IOException.class,
                () -> MessageCodec.readFrame(in)
        );
    }
}
