package com.adaptpqc;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class Main {

    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());

        System.out.println("=================================");
        System.out.println("        ADAPT-PQC");
        System.out.println("=================================");
        System.out.println();

        System.out.println("Bouncy Castle Provider:");

        if (Security.getProvider("BC") != null) {
            System.out.println("BC provider loaded successfully.");
        } else {
            System.out.println("ERROR: BC provider not loaded.");
        }

        System.out.println();
        System.out.println("Week 1 Crypto Core");
        System.out.println("-------------------");
        System.out.println("ML-KEM");
        System.out.println("HKDF");
        System.out.println("AES-GCM");
    }
}