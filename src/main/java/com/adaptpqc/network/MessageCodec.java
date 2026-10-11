
package com.adaptpqc.network;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;

public final class MessageCodec {

    private static final int MAX_MESSAGE_SIZE = 1_048_576; // 1 MiB

    private MessageCodec() {
        // Utility class
    }

    public static void writeFrame(
            DataOutputStream out,
            byte[] message
    ) throws IOException {

        if (out == null || message == null) {
            throw new IllegalArgumentException(
                    "Output stream and message must not be null"
            );
        }

        if (message.length == 0 ||
                message.length > MAX_MESSAGE_SIZE) {
            throw new IOException(
                    "Invalid message size: " + message.length
            );
        }

        out.writeInt(message.length);
        out.write(message);
        out.flush();
    }

    public static byte[] readFrame(
            DataInputStream in
    ) throws IOException {

        if (in == null) {
            throw new IllegalArgumentException(
                    "Input stream must not be null"
            );
        }

        final int length;

        try {
            length = in.readInt();
        } catch (EOFException e) {
            // The peer closed the connection before another frame.
            throw e;
        }

        if (length <= 0 || length > MAX_MESSAGE_SIZE) {
            throw new IOException(
                    "Invalid incoming message size: " + length
            );
        }

        byte[] message = new byte[length];
        in.readFully(message);

        return message;
    }
}
