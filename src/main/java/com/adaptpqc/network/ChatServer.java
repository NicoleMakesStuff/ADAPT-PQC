
package com.adaptpqc.network;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.UUID;

import com.adaptpqc.protocol.v2.ProtocolSession;
import com.adaptpqc.protocol.v2.SecureMessage;
import com.adaptpqc.protocol.v2.SecureMessageService;
import com.adaptpqc.protocol.v2.SecureMessageWireCodec;

public final class ChatServer {

    private static final int PORT = 5000;

    // DEMO ONLY: shared test material for localhost.
    // Never hardcode production cryptographic secrets.
    private static final byte[] SHARED_SECRET =
            "ADAPT-PQC-demo-secret-change-before-deployment"
                    .getBytes(StandardCharsets.UTF_8);

    private static final byte[] SESSION_SALT =
            "ADAPT-PQC-demo-salt"
                    .getBytes(StandardCharsets.UTF_8);

    private static final UUID SESSION_ID =
            UUID.fromString("2a6a4d32-2a25-4e4e-9b1e-18d61f904b01");

    public static void main(String[] args) {
        System.out.println("ADAPT-PQC encrypted chat server starting...");

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println(
                    "Listening on port " + PORT
                            + ". Waiting for Alice..."
            );

            while (true) {
                try (Socket socket = serverSocket.accept()) {
                    socket.setSoTimeout(120_000);

                    System.out.println(
                            "Client connected: "
                                    + socket.getRemoteSocketAddress()
                    );

                    handleClient(socket);

                } catch (IOException e) {
                    System.err.println(
                            "Connection ended: " + e.getMessage()
                    );
                } catch (GeneralSecurityException e) {
                    System.err.println(
                            "Cryptographic error: " + e.getMessage()
                    );
                }
            }

        } catch (IOException e) {
            System.err.println(
                    "Server failed: " + e.getMessage()
            );
        }
    }

    private static void handleClient(Socket socket)
            throws IOException, GeneralSecurityException {

        ProtocolSession protocolSession =
                new ProtocolSession(SHARED_SECRET, SESSION_SALT);

        SecureMessageService service =
                new SecureMessageService(SESSION_ID, protocolSession);

        try (
                DataInputStream in = new DataInputStream(
                        socket.getInputStream());
                DataOutputStream out = new DataOutputStream(
                        socket.getOutputStream())
        ) {
            while (true) {
                final byte[] frame;

                try {
                    frame = MessageCodec.readFrame(in);
                } catch (EOFException e) {
                    System.out.println("Alice disconnected.");
                    break;
                }

                SecureMessage incoming =
                        SecureMessageWireCodec.decode(frame);

                // Only display plaintext after authentication succeeds.
                String plaintext = service.decrypt(incoming);

                System.out.println("Alice (verified): " + plaintext);

                if ("/quit".equalsIgnoreCase(plaintext.trim())) {
                    break;
                }

                String reply = "Bob received: " + plaintext;

                SecureMessage outgoing = service.encrypt(reply);

                byte[] encoded =
                        SecureMessageWireCodec.encode(outgoing);

                MessageCodec.writeFrame(out, encoded);
            }
        } finally {
            protocolSession.abort();
        }
    }
}
