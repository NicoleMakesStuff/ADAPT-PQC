
package com.adaptpqc.network;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Scanner;
import java.util.UUID;

import com.adaptpqc.protocol.v2.ProtocolSession;
import com.adaptpqc.protocol.v2.SecureMessage;
import com.adaptpqc.protocol.v2.SecureMessageService;
import com.adaptpqc.protocol.v2.SecureMessageWireCodec;

public final class ChatClient {

    private static final String HOST = "127.0.0.1";
    private static final int PORT = 5000;

    // Must match the server for this localhost demonstration.
    private static final byte[] SHARED_SECRET =
            "ADAPT-PQC-demo-secret-change-before-deployment"
                    .getBytes(StandardCharsets.UTF_8);

    private static final byte[] SESSION_SALT =
            "ADAPT-PQC-demo-salt"
                    .getBytes(StandardCharsets.UTF_8);

    private static final UUID SESSION_ID =
            UUID.fromString("2a6a4d32-2a25-4e4e-9b1e-18d61f904b01");

    public static void main(String[] args) {
        System.out.println("ADAPT-PQC encrypted chat client starting...");

        try (
                Socket socket = new Socket(HOST, PORT);
                DataInputStream in = new DataInputStream(
                        socket.getInputStream());
                DataOutputStream out = new DataOutputStream(
                        socket.getOutputStream());
                Scanner scanner = new Scanner(System.in)
        ) {
            socket.setSoTimeout(120_000);

            ProtocolSession protocolSession =
                    new ProtocolSession(SHARED_SECRET, SESSION_SALT);

            try {
                SecureMessageService service =
                        new SecureMessageService(
                                SESSION_ID, protocolSession);

                System.out.println("Connected to Bob.");
                System.out.println(
                        "Messages are encrypted and authenticated."
                );
                System.out.println("Type /quit to exit.");

                while (true) {
                    System.out.print("Alice > ");

                    if (!scanner.hasNextLine()) {
                        break;
                    }

                    String plaintext = scanner.nextLine();

                    SecureMessage outgoing =
                            service.encrypt(plaintext);

                    byte[] encoded =
                            SecureMessageWireCodec.encode(outgoing);

                    MessageCodec.writeFrame(out, encoded);

                    if ("/quit".equalsIgnoreCase(plaintext.trim())) {
                        break;
                    }

                    byte[] responseFrame = MessageCodec.readFrame(in);

                    SecureMessage response =
                            SecureMessageWireCodec.decode(responseFrame);

                    // Reject the reply if its session, sequence,
                    // generation, or HMAC is invalid.
                    String verifiedReply = service.decrypt(response);

                    System.out.println("Bob (verified): " + verifiedReply);
                }
            } finally {
                protocolSession.abort();
            }

        } catch (IOException | GeneralSecurityException e) {
            System.err.println(
                    "Client error: " + e.getMessage()
            );
        }
    }
}
