package com.christoskarakoutis.authenticationsystem.mfa;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.OptionalLong;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;


public final class Totp {
    private static final String MAC_ALGORITHM = "HmacSHA256";

    private Totp() {};

    public static String generate(byte[] key, long counter, int digits) {
        byte[] hash = hmac(key, counter);

        int offset = hash[hash.length - 1] & 0x0f;
        int binary = ((hash[offset]     & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                |  (hash[offset + 3] & 0xff);

        int otp = binary % (int) Math.pow(10, digits);
        return String.format("%0" + digits + "d", otp);
    }

    public static OptionalLong verify(byte[] key, String code, long currentCounter, long lastUsedCounter, int digits) {
        byte[] submitted = code.getBytes(StandardCharsets.US_ASCII);

        for(long counter = currentCounter - 1; counter <= currentCounter + 1; counter++) {
            if(counter <= lastUsedCounter) {
                continue;
            }

            byte[] expected = generate(key, counter, digits).getBytes(StandardCharsets.US_ASCII);
            if (MessageDigest.isEqual(expected, submitted)) {
                return OptionalLong.of(counter);
            }
        }

        return OptionalLong.empty();
    }

    private static byte[] hmac(byte[] key, long counter) {
        try {
            Mac mac = Mac.getInstance(MAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, MAC_ALGORITHM));
            return mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException((e));
        }
    }
}
