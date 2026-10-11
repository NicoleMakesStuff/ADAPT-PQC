
package com.adaptpqc.protocol.v2;

import java.io.IOException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

class SecureMessageWireCodecTest {

    @Test
    void rejectsNullInput() {
        assertThrows(
                IOException.class,
                () -> SecureMessageWireCodec.decode(null)
        );
    }

    @Test
    void rejectsEmptyInput() {
        assertThrows(
                IOException.class,
                () -> SecureMessageWireCodec.decode(new byte[0])
        );
    }

    @Test
    void rejectsTruncatedInput() {
        assertThrows(
                IOException.class,
                () -> SecureMessageWireCodec.decode(
                        new byte[]{0x41, 0x50, 0x51}
                )
        );
    }

    @Test
    void rejectsInvalidMagic() {
        byte[] invalid = new byte[32];

        assertThrows(
                IOException.class,
                () -> SecureMessageWireCodec.decode(invalid)
        );
    }

    @Test
    void rejectsTrailingBytes() throws Exception {
        SecureMessage message = createMessage();

        byte[] encoded = SecureMessageWireCodec.encode(message);
        byte[] withTrailingByte =
                java.util.Arrays.copyOf(encoded, encoded.length + 1);

        assertThrows(
                IOException.class,
                () -> SecureMessageWireCodec.decode(withTrailingByte)
        );
    }

    private SecureMessage createMessage() {
        byte[] nonce = new byte[12];
        byte[] ciphertext = new byte[]{1, 2, 3, 4};
        byte[] authenticationTag = new byte[32];

        ProtocolCrypto.EncryptedPayload payload =
                new ProtocolCrypto.EncryptedPayload(
                        nonce, ciphertext);

        return new SecureMessage(
                UUID.randomUUID(),
                0,
                0,
                payload,
                authenticationTag);
    }
}
