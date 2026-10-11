
package com.adaptpqc.protocol.v2;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.UUID;

import javax.crypto.KEM;

import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class RatchetProtocol {

    private RatchetProtocol() {}

    private static void ensureProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static KeyPair generateMlKemKeyPair()
            throws GeneralSecurityException {
        ensureProvider();

        var generator =
                java.security.KeyPairGenerator.getInstance("ML-KEM", "BC");
        generator.initialize(MLKEMParameterSpec.ml_kem_768);
        return generator.generateKeyPair();
    }

    public static Initiator begin(
            ProtocolSession session,
            PublicKey recipientPublicKey)
            throws GeneralSecurityException {

        if (session == null || recipientPublicKey == null) {
            throw new IllegalArgumentException(
                    "Session and recipient key are required");
        }

        ensureProvider();

        int nextGeneration = session.generation() + 1;

        KEM kem = KEM.getInstance("ML-KEM", "BC");
        KEM.Encapsulated encapsulated =
                kem.newEncapsulator(recipientPublicKey).encapsulate();

        byte[] sharedSecret = encapsulated.key().getEncoded();
        byte[] salt = ProtocolCrypto.randomBytes(32);
        UUID offerId = UUID.randomUUID();

        session.preparePending(sharedSecret, salt, nextGeneration);

        RatchetOfferMessage unsignedOffer =
                new RatchetOfferMessage(
                        offerId,
                        nextGeneration,
                        encapsulated.encapsulation(),
                        salt,
                        new byte[]{1});

        byte[] tag = ProtocolCrypto.mac(
                session.activeAuthKey(),
                unsignedOffer.authenticatedBytes());

        return new Initiator(session, unsignedOffer.withTag(tag));
    }

    public static final class Initiator {
        private final ProtocolSession session;
        private final RatchetOfferMessage offer;
        private boolean completed;

        private Initiator(
                ProtocolSession session,
                RatchetOfferMessage offer) {
            this.session = session;
            this.offer = offer;
        }

        public RatchetOfferMessage offer() {
            return offer;
        }

        public synchronized RatchetFinalAck acceptConfirmation(
                RatchetConfirmation confirmation)
                throws GeneralSecurityException {

            if (completed) {
                throw new GeneralSecurityException(
                        "Exchange already completed");
            }

            if (confirmation == null
                    || !offer.offerId().equals(confirmation.offerId())
                    || confirmation.generation()
                    != offer.nextGeneration()) {
                throw new GeneralSecurityException(
                        "Confirmation does not match offer");
            }

            if (!ProtocolCrypto.verifyMac(
                    session.activeAuthKey(),
                    confirmation.authenticatedBytes(),
                    confirmation.authenticationTag())) {
                session.abort();
                completed = true;
                throw new GeneralSecurityException(
                        "Invalid confirmation authentication");
            }

            session.commitPending();

            RatchetFinalAck unsignedAck =
                    new RatchetFinalAck(
                            offer.offerId(),
                            offer.nextGeneration(),
                            new byte[]{1});

            byte[] tag = ProtocolCrypto.mac(
                    session.activeAuthKey(),
                    unsignedAck.authenticatedBytes());

            completed = true;

            return unsignedAck.withTag(tag);
        }

        public synchronized void abort() {
            if (!completed) {
                session.abort();
                completed = true;
            }
        }
    }

    public static final class Responder {
        private final ProtocolSession session;
        private final PrivateKey privateKey;
        private final ReplayGuard replayGuard;

        private RatchetOfferMessage pendingOffer;

        public Responder(
                ProtocolSession session,
                PrivateKey privateKey,
                int replayCapacity) {

            if (session == null || privateKey == null) {
                throw new IllegalArgumentException(
                        "Session and private key are required");
            }

            this.session = session;
            this.privateKey = privateKey;
            this.replayGuard = new ReplayGuard(replayCapacity);
        }

        public synchronized RatchetConfirmation receiveOffer(
                RatchetOfferMessage offer)
                throws GeneralSecurityException {

            if (pendingOffer != null) {
                throw new GeneralSecurityException(
                        "Responder already has a pending exchange");
            }

            if (offer == null) {
                throw new GeneralSecurityException("Offer is null");
            }

            if (offer.nextGeneration() != session.generation() + 1) {
                throw new GeneralSecurityException(
                        "Stale or skipped generation");
            }

            if (!ProtocolCrypto.verifyMac(
                    session.activeAuthKey(),
                    offer.authenticatedBytes(),
                    offer.authenticationTag())) {
                throw new GeneralSecurityException(
                        "Invalid offer authentication");
            }

            if (!replayGuard.accept(offer.offerId())) {
                throw new GeneralSecurityException("Duplicate offer");
            }

            ensureProvider();

            KEM kem = KEM.getInstance("ML-KEM", "BC");
            byte[] sharedSecret = kem
                    .newDecapsulator(privateKey)
                    .decapsulate(offer.encapsulation())
                    .getEncoded();

            session.preparePending(
                    sharedSecret,
                    offer.salt(),
                    offer.nextGeneration());

            pendingOffer = offer;

            RatchetConfirmation unsignedConfirmation =
                    new RatchetConfirmation(
                            offer.offerId(),
                            offer.nextGeneration(),
                            new byte[]{1});

            byte[] tag = ProtocolCrypto.mac(
                    session.activeAuthKey(),
                    unsignedConfirmation.authenticatedBytes());

            return unsignedConfirmation.withTag(tag);
        }

        public synchronized void receiveFinalAck(RatchetFinalAck ack)
                throws GeneralSecurityException {

            if (pendingOffer == null) {
                throw new GeneralSecurityException(
                        "No pending ratchet exchange");
            }

            if (ack == null
                    || !pendingOffer.offerId().equals(ack.offerId())
                    || ack.generation()
                    != pendingOffer.nextGeneration()) {
                throw new GeneralSecurityException(
                        "Final acknowledgement mismatch");
            }

            if (!ProtocolCrypto.verifyMac(
                    session.pendingAuthKey(),
                    ack.authenticatedBytes(),
                    ack.authenticationTag())) {
                session.abort();
                pendingOffer = null;

                throw new GeneralSecurityException(
                        "Invalid final acknowledgement");
            }

            session.commitPending();
            pendingOffer = null;
        }

        public synchronized void abort() {
            session.abort();
            pendingOffer = null;
        }
    }
}
