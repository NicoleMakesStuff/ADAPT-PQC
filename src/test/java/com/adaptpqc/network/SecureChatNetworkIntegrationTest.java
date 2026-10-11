
package com.adaptpqc.network;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

import com.adaptpqc.protocol.v2.ProtocolSession;
import com.adaptpqc.protocol.v2.SecureMessage;
import com.adaptpqc.protocol.v2.SecureMessageService;
import com.adaptpqc.protocol.v2.SecureMessageWireCodec;

class SecureChatNetworkIntegrationTest {

    private static final byte[] SECRET =
            "integration-test-shared-secret"
                    .getBytes(StandardCharsets.UTF_8);

    private static final byte[] SALT =
            "integration-test-salt"
                    .getBytes(StandardCharsets.UTF_8);

    private static final UUID SESSION_ID =
            UUID.fromString("2a6a4d32-2a25-4e4e-9b1e-18d61f904b01");

    private SecureMessageService newService()
            throws GeneralSecurityException {

        return new SecureMessageService(
                SESSION_ID,
                new ProtocolSession(SECRET, SALT));
    }

    @Test
    void encryptedMessageAndReplyTravelOverTcp() throws Exception {
        AtomicReference<Throwable> serverError =
                new AtomicReference<>();

        try (ServerSocket server = new ServerSocket(
                0, 1, InetAddress.getLoopbackAddress())) {

            int port = server.getLocalPort();

            Thread serverThread = new Thread(() -> {
                try (
                        Socket socket = server.accept();
                        DataInputStream in = new DataInputStream(
                                socket.getInputStream());
                        DataOutputStream out = new DataOutputStream(
                                socket.getOutputStream())
                ) {
                    socket.setSoTimeout(5000);

                    SecureMessageService bob = newService();

                    byte[] requestFrame = MessageCodec.readFrame(in);
                    SecureMessage request =
                            SecureMessageWireCodec.decode(requestFrame);

                    String received = bob.decrypt(request);
                    assertEquals("Hello Bob", received);

                    SecureMessage reply =
                            bob.encrypt("Hello Alice");

                    MessageCodec.writeFrame(
                            out,
                            SecureMessageWireCodec.encode(reply));

                } catch (Throwable t) {
                    serverError.set(t);
                }
            });

            serverThread.start();

            try (
                    Socket socket = new Socket(
                            InetAddress.getLoopbackAddress(), port);
                    DataInputStream in = new DataInputStream(
                            socket.getInputStream());
                    DataOutputStream out = new DataOutputStream(
                            socket.getOutputStream())
            ) {
                socket.setSoTimeout(5000);

                SecureMessageService alice = newService();

                SecureMessage request = alice.encrypt("Hello Bob");

                MessageCodec.writeFrame(
                        out,
                        SecureMessageWireCodec.encode(request));

                byte[] responseFrame = MessageCodec.readFrame(in);
                SecureMessage response =
                        SecureMessageWireCodec.decode(responseFrame);

                assertEquals("Hello Alice", alice.decrypt(response));
            }

            serverThread.join(5000);

            assertFalse(
                    serverThread.isAlive(),
                    "Server thread should finish");
            assertNull(
                    serverError.get(),
                    "Server encountered an error: " + serverError.get());
        }
    }

    @Test
    void tamperedAuthenticationTagIsRejected() throws Exception {
        SecureMessageService alice = newService();
        SecureMessageService bob = newService();

        SecureMessage original = alice.encrypt("Do not alter this");
        byte[] encoded = SecureMessageWireCodec.encode(original);

        // The authentication tag is the final 32 bytes in this format.
        encoded[encoded.length - 1] ^= 0x01;

        SecureMessage tampered =
                SecureMessageWireCodec.decode(encoded);

        assertThrows(
                GeneralSecurityException.class,
                () -> bob.decrypt(tampered));
    }

    @Test
    void replayedMessageIsRejected() throws Exception {
        SecureMessageService alice = newService();
        SecureMessageService bob = newService();

        SecureMessage original = alice.encrypt("One-time message");

        byte[] encoded = SecureMessageWireCodec.encode(original);

        SecureMessage firstCopy =
                SecureMessageWireCodec.decode(encoded);
        SecureMessage replayCopy =
                SecureMessageWireCodec.decode(encoded);

        assertEquals("One-time message", bob.decrypt(firstCopy));

        assertThrows(
                GeneralSecurityException.class,
                () -> bob.decrypt(replayCopy));
    }
}
