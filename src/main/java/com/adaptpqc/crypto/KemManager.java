package com.adaptpqc.crypto;

import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KEM;
import javax.crypto.SecretKey;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

public class KemManager {

    private static final String PROVIDER = "BC";
    private static final String ALGORITHM = "ML-KEM";

    private static final MLKEMParameterSpec PARAMETER_SET =
            MLKEMParameterSpec.ml_kem_768;

    static {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Generates an ML-KEM-768 key pair.
     */
    public KeyPair generateKeyPair() throws Exception {

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance(
                        ALGORITHM,
                        PROVIDER
                );

        generator.initialize(
                PARAMETER_SET,
                new SecureRandom()
        );

        return generator.generateKeyPair();
    }

    /**
     * Performs ML-KEM encapsulation using the receiver's
     * public key.
     *
     * Returns:
     *  - encapsulation ciphertext
     *  - shared secret
     */
    public KemEncapsulationResult encapsulate(
            PublicKey publicKey) throws Exception {

        KEM kem =
                KEM.getInstance(
                        ALGORITHM,
                        PROVIDER
                );

        KEM.Encapsulator encapsulator =
                kem.newEncapsulator(
                        publicKey,
                        new SecureRandom()
                );

        KEM.Encapsulated encapsulated =
                encapsulator.encapsulate();

        SecretKey sharedSecret =
                encapsulated.key();

        return new KemEncapsulationResult(
                encapsulated.encapsulation(),
                sharedSecret.getEncoded()
        );
    }

    /**
     * Performs ML-KEM decapsulation using the
     * receiver's private key.
     */
    public byte[] decapsulate(
            PrivateKey privateKey,
            byte[] ciphertext) throws Exception {

        KEM kem =
                KEM.getInstance(
                        ALGORITHM,
                        PROVIDER
                );

        KEM.Decapsulator decapsulator =
                kem.newDecapsulator(privateKey);

        SecretKey sharedSecret =
                decapsulator.decapsulate(ciphertext);

        return sharedSecret.getEncoded();
    }
}