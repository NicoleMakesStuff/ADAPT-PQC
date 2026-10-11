
package com.adaptpqc.ratchet;

import java.security.KeyPair;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

import com.adaptpqc.crypto.CryptoSession;
import com.adaptpqc.crypto.KemManager;
import com.adaptpqc.session.SessionState;

class RatchetServiceTest {

    @Test
    void ratchetShouldSynchronizeKeysAndAdvanceGeneration()
            throws Exception {

        KemManager kem = new KemManager();

        KeyPair recipientKeys = kem.generateKeyPair();

        // Establish an initial shared session key.
        var initial = kem.encapsulate(recipientKeys.getPublic());

        byte[] recipientSecret = kem.decapsulate(
                recipientKeys.getPrivate(),
                initial.getCiphertext()
        );

        byte[] initialSalt = new byte[32];
        new SecureRandom().nextBytes(initialSalt);

        CryptoSession initiatorCrypto = new CryptoSession(
                initial.getSharedSecret(),
                initialSalt
        );

        CryptoSession recipientCrypto = new CryptoSession(
                recipientSecret,
                initialSalt
        );

        SessionState initiatorState = new SessionState();
        SessionState recipientState = new SessionState();

        RatchetService service = new RatchetService();

        // Initiator prepares a new key generation.
        PreparedRatchet prepared = service.prepare(
                initiatorState,
                recipientKeys.getPublic()
        );

        assertEquals(
                0,
                initiatorState.getKeyGeneration()
        );

        // Recipient derives the new key.
        service.accept(
                recipientState,
                recipientCrypto,
                recipientKeys.getPrivate(),
                prepared.getOffer()
        );

        // Simulate authenticated acceptance for this local test.
        service.commit(
                initiatorState,
                initiatorCrypto,
                prepared
        );

        assertEquals(
                1,
                initiatorState.getKeyGeneration()
        );

        assertEquals(
                1,
                recipientState.getKeyGeneration()
        );

        // Verify the new keys match by encrypting on one side
        // and decrypting on the other.
        var encrypted = initiatorCrypto.encrypt(
                "Message after ratchet"
        );

        assertEquals(
                "Message after ratchet",
                recipientCrypto.decrypt(encrypted)
        );
    }

    @Test
    void invalidGenerationShouldBeRejected() throws Exception {
        KemManager kem = new KemManager();
        KeyPair keys = kem.generateKeyPair();

        var initial = kem.encapsulate(keys.getPublic());

        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);

        CryptoSession crypto = new CryptoSession(
                initial.getSharedSecret(),
                salt
        );

        SessionState session = new SessionState();

        RatchetService service = new RatchetService();

        RatchetOffer wrongGeneration = new RatchetOffer(
                initial.getCiphertext(),
                salt,
                99
        );

        assertThrows(
                IllegalStateException.class,
                () -> service.accept(
                        session,
                        crypto,
                        keys.getPrivate(),
                        wrongGeneration
                )
        );

        assertEquals(0, session.getKeyGeneration());
    }
}
