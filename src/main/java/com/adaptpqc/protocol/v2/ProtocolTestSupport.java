
package com.adaptpqc.protocol.v2;

import java.security.GeneralSecurityException;

public final class ProtocolTestSupport {

    private ProtocolTestSupport() {
    }

    public static SecureMessage tamperAuthenticationTag(
            SecureMessage original)
            throws GeneralSecurityException {

        byte[] alteredTag = original.authenticationTag();
        alteredTag[0] ^= 0x01;

        return new SecureMessage(
                original.sessionId(),
                original.sequenceNumber(),
                original.generation(),
                original.payload(),
                alteredTag
        );
    }
}
