
package com.adaptpqc.protocol.v2;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.UUID;

public final class SecureMessageWireCodec {

    private static final int MAGIC = 0x41505143; // "APQC"
    private static final short VERSION = 1;

    private static final int UUID_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int AUTH_TAG_BYTES = 32;

    private static final int MAX_CIPHERTEXT_BYTES = 1_048_576;
    private static final int MAX_WIRE_BYTES =
            4 + 2 + UUID_BYTES + 8 + 4
                    + 4 + NONCE_BYTES
                    + 4 + MAX_CIPHERTEXT_BYTES
                    + 4 + AUTH_TAG_BYTES;

    private SecureMessageWireCodec() {
    }

    public static byte[] encode(SecureMessage message)
            throws IOException {

        if (message == null) {
            throw new IllegalArgumentException(
                    "Message must not be null");
        }

        ProtocolCrypto.EncryptedPayload payload = message.payload();

        byte[] nonce = payload.nonce();
        byte[] ciphertext = payload.ciphertext();
        byte[] authenticationTag = message.authenticationTag();

        if (nonce == null || nonce.length != NONCE_BYTES) {
            throw new IOException("Invalid AES-GCM nonce");
        }

        if (ciphertext == null
                || ciphertext.length == 0
                || ciphertext.length > MAX_CIPHERTEXT_BYTES) {
            throw new IOException("Invalid ciphertext length");
        }

        if (authenticationTag.length != AUTH_TAG_BYTES) {
            throw new IOException("Invalid authentication tag length");
        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(buffer);

        out.writeInt(MAGIC);
        out.writeShort(VERSION);

        out.writeLong(message.sessionId().getMostSignificantBits());
        out.writeLong(message.sessionId().getLeastSignificantBits());

        out.writeLong(message.sequenceNumber());
        out.writeInt(message.generation());

        out.writeInt(nonce.length);
        out.write(nonce);

        out.writeInt(ciphertext.length);
        out.write(ciphertext);

        out.writeInt(authenticationTag.length);
        out.write(authenticationTag);

        out.flush();

        byte[] result = buffer.toByteArray();

        if (result.length > MAX_WIRE_BYTES) {
            throw new IOException("Encoded message is too large");
        }

        return result;
    }

    public static SecureMessage decode(byte[] encoded)
            throws IOException {

        if (encoded == null
                || encoded.length == 0
                || encoded.length > MAX_WIRE_BYTES) {
            throw new IOException("Invalid wire message size");
        }

        try {
            ByteArrayInputStream buffer =
                    new ByteArrayInputStream(encoded);
            DataInputStream in = new DataInputStream(buffer);

            int magic = in.readInt();
            if (magic != MAGIC) {
                throw new IOException("Invalid protocol magic");
            }

            short version = in.readShort();
            if (version != VERSION) {
                throw new IOException(
                        "Unsupported protocol version: " + version);
            }

            UUID sessionId = new UUID(
                    in.readLong(),
                    in.readLong());

            long sequenceNumber = in.readLong();
            int generation = in.readInt();

            if (sequenceNumber < 0 || generation < 0) {
                throw new IOException(
                        "Invalid sequence number or generation");
            }

            int nonceLength = in.readInt();
            if (nonceLength != NONCE_BYTES) {
                throw new IOException("Invalid nonce length");
            }

            byte[] nonce = new byte[nonceLength];
            in.readFully(nonce);

            int ciphertextLength = in.readInt();
            if (ciphertextLength <= 0
                    || ciphertextLength > MAX_CIPHERTEXT_BYTES) {
                throw new IOException("Invalid ciphertext length");
            }

            byte[] ciphertext = new byte[ciphertextLength];
            in.readFully(ciphertext);

            int tagLength = in.readInt();
            if (tagLength != AUTH_TAG_BYTES) {
                throw new IOException(
                        "Invalid authentication tag length");
            }

            byte[] authenticationTag = new byte[tagLength];
            in.readFully(authenticationTag);

            if (in.available() != 0) {
                throw new IOException(
                        "Unexpected trailing bytes");
            }

            ProtocolCrypto.EncryptedPayload payload =
                    new ProtocolCrypto.EncryptedPayload(
                            nonce,
                            ciphertext);

            return new SecureMessage(
                    sessionId,
                    sequenceNumber,
                    generation,
                    payload,
                    authenticationTag);

        } catch (IOException e) {
            throw e;
        } catch (IllegalArgumentException e) {
            throw new IOException("Malformed secure message", e);
        }
    }
}
