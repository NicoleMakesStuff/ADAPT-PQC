
package com.adaptpqc.ratchet;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import com.adaptpqc.crypto.CryptoSession;
import com.adaptpqc.crypto.KemEncapsulationResult;
import com.adaptpqc.crypto.KemManager;
import com.adaptpqc.session.SessionState;

public class RatchetService {

    private final KemManager kemManager;
    private final SecureRandom secureRandom;

    public RatchetService() {
        this.kemManager = new KemManager();
        this.secureRandom = new SecureRandom();
    }

    /**
     * Initiator prepares a new key generation.
     * The current session key is not changed yet.
     */
    public PreparedRatchet prepare(
            SessionState session,
            PublicKey recipientPublicKey) throws Exception {

        if (session == null || recipientPublicKey == null) {
            throw new IllegalArgumentException(
                    "Session and recipient public key are required."
            );
        }

        KemEncapsulationResult result =
                kemManager.encapsulate(recipientPublicKey);

        byte[] salt = new byte[32];
        secureRandom.nextBytes(salt);

        long nextGeneration =
                session.getKeyGeneration() + 1;

        RatchetOffer offer = new RatchetOffer(
                result.getCiphertext(),
                salt,
                nextGeneration
        );

        return new PreparedRatchet(
                offer,
                result.getSharedSecret()
        );
    }

    /**
     * Recipient processes an offer and derives the new key.
     *
     * In a real protocol, validate the offer's authentication,
     * session identity, and generation before committing.
     */
    public synchronized void accept(
            SessionState session,
            CryptoSession cryptoSession,
            PrivateKey recipientPrivateKey,
            RatchetOffer offer) throws Exception {

        validateInputs(
                session,
                cryptoSession,
                offer
        );

        if (recipientPrivateKey == null) {
            throw new IllegalArgumentException(
                    "Recipient private key is required."
            );
        }

        validateGeneration(session, offer);

        byte[] sharedSecret = kemManager.decapsulate(
                recipientPrivateKey,
                offer.getEncapsulation()
        );

        cryptoSession.rotateKey(
                sharedSecret,
                offer.getSalt()
        );

        session.incrementKeyGeneration();
    }

    /**
     * Initiator commits its pending key after the protocol
     * confirms that the recipient accepted the offer.
     *
     * This method assumes confirmation has already been
     * authenticated by the caller. That protocol is not
     * implemented in this stage.
     */
    public synchronized void commit(
            SessionState session,
            CryptoSession cryptoSession,
            PreparedRatchet prepared) throws Exception {

        if (prepared == null) {
            throw new IllegalArgumentException(
                    "Prepared ratchet is required."
            );
        }

        validateInputs(
                session,
                cryptoSession,
                prepared.getOffer()
        );

        validateGeneration(session, prepared.getOffer());

        cryptoSession.rotateKey(
                prepared.getPendingSharedSecret(),
                prepared.getOffer().getSalt()
        );

        session.incrementKeyGeneration();
    }

    private void validateInputs(
            SessionState session,
            CryptoSession cryptoSession,
            RatchetOffer offer) {

        if (session == null
                || cryptoSession == null
                || offer == null) {
            throw new IllegalArgumentException(
                    "Session, crypto session, and offer are required."
            );
        }
    }

    private void validateGeneration(
            SessionState session,
            RatchetOffer offer) {

        if (offer.getNextGeneration()
                != session.getKeyGeneration() + 1) {
            throw new IllegalStateException(
                    "Unexpected ratchet generation."
            );
        }
    }
}
