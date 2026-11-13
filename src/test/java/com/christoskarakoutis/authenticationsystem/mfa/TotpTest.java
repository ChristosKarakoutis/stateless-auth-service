package com.christoskarakoutis.authenticationsystem.mfa;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class TotpTest {

    // RFC 6238 Appendix B, SHA-256 secret: 32 ASCII bytes
    private static final byte[] KEY_SHA256 =
            "12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);

    // T = 1111111111 -> floor(T / 30)
    private static final long CURRENT_COUNTER = 37037037L;

    // ---------- generate ----------

    @ParameterizedTest(name = "T={0} -> counter {1} -> {2}")
    @DisplayName("RFC 6238 Appendix B vectors (SHA-256, 8 digits)")
    @CsvSource({
            "59,          1,         46119246",
            "1111111109,  37037036,  68084774",
            "1111111111,  37037037,  67062674",
            "1234567890,  41152263,  91819424",
            "2000000000,  66666666,  90698825",
            "20000000000, 666666666, 77737706"
    })
    void generate_matchesRfcVectors(long time, long counter, String expected) {
        // Το counter είναι floor(T / 30), όπως ορίζει το RFC 6238 §4.2
        assertThat(time / 30).isEqualTo(counter);

        assertThat(Totp.generate(KEY_SHA256, counter, 8)).isEqualTo(expected);
    }

    @Test
    @DisplayName("6 digits are the last 6 digits of the 8-digit value")
    void generate_sixDigits_isSuffixOfEightDigits() {
        // 10^6 διαιρεί το 10^8, άρα (x mod 10^8) mod 10^6 = x mod 10^6
        assertThat(Totp.generate(KEY_SHA256, 1, 6)).isEqualTo("119246");
    }

    @Test
    @DisplayName("codes with leading zeros keep them")
    void generate_leadingZero_isPadded() {
        // Το 8-ψήφιο 68084774 δίνει 6ψήφιο 084774: το μηδέν πρέπει να μείνει
        String code = Totp.generate(KEY_SHA256, 37037036, 6);

        assertThat(code).hasSize(6).isEqualTo("084774");
    }

    @Test
    @DisplayName("same key and counter always give the same code")
    void generate_isDeterministic() {
        assertThat(Totp.generate(KEY_SHA256, 1234, 6))
                .isEqualTo(Totp.generate(KEY_SHA256, 1234, 6));
    }

    @Test
    @DisplayName("a different key gives a different code")
    void generate_differentKey_differentCode() {
        byte[] otherKey = "00000000000000000000000000000000".getBytes(StandardCharsets.US_ASCII);

        assertThat(Totp.generate(otherKey, 1, 8))
                .isNotEqualTo(Totp.generate(KEY_SHA256, 1, 8));
    }

    // ---------- verify ----------

    @ParameterizedTest(name = "offset {0} is accepted")
    @DisplayName("codes from the drift window (now-1, now, now+1) are accepted")
    @CsvSource({"-1", "0", "1"})
    void verify_acceptsCodesInsideWindow(long offset) {
        String code = code(CURRENT_COUNTER + offset);

        assertThat(Totp.verify(KEY_SHA256, code, CURRENT_COUNTER, -1L, 6))
                .hasValue(CURRENT_COUNTER + offset);
    }

    @ParameterizedTest(name = "offset {0} is rejected")
    @DisplayName("codes two steps away from now are rejected")
    @CsvSource({"-2", "2"})
    void verify_rejectsCodesOutsideWindow(long offset) {
        String code = code(CURRENT_COUNTER + offset);

        assertThat(Totp.verify(KEY_SHA256, code, CURRENT_COUNTER, -1L, 6)).isEmpty();
    }

    @Test
    @DisplayName("a code already used at the current step is rejected (replay)")
    void verify_replayOfLastUsedCounter_isRejected() {
        String code = code(CURRENT_COUNTER);

        assertThat(Totp.verify(KEY_SHA256, code, CURRENT_COUNTER, CURRENT_COUNTER, 6)).isEmpty();
    }

    @Test
    @DisplayName("codes from steps before the last used counter are rejected")
    void verify_codesBeforeLastUsed_areRejected() {
        // Το lastUsed είναι το τρέχον: τα now-1 και now πρέπει να απορριφθούν
        long lastUsed = CURRENT_COUNTER;

        assertThat(Totp.verify(KEY_SHA256, code(CURRENT_COUNTER - 1), CURRENT_COUNTER, lastUsed, 6)).isEmpty();
        assertThat(Totp.verify(KEY_SHA256, code(CURRENT_COUNTER), CURRENT_COUNTER, lastUsed, 6)).isEmpty();
    }

    @Test
    @DisplayName("a newer step is still accepted after an older one was used")
    void verify_newerStepAfterLastUsed_isAccepted() {
        long lastUsed = CURRENT_COUNTER;
        String code = code(CURRENT_COUNTER + 1);

        assertThat(Totp.verify(KEY_SHA256, code, CURRENT_COUNTER, lastUsed, 6))
                .hasValue(CURRENT_COUNTER + 1);
    }

    @Test
    @DisplayName("a wrong code is rejected")
    void verify_wrongCode_isRejected() {
        assertThat(Totp.verify(KEY_SHA256, "000000", CURRENT_COUNTER, -1L, 6)).isEmpty();
    }

    @Test
    @DisplayName("a code with the wrong number of digits is rejected")
    void verify_wrongLength_isRejected() {
        String shortCode = code(CURRENT_COUNTER).substring(0, 5);

        assertThat(Totp.verify(KEY_SHA256, shortCode, CURRENT_COUNTER, -1L, 6)).isEmpty();
    }

    @Test
    @DisplayName("a code generated with another key is rejected")
    void verify_codeFromOtherKey_isRejected() {
        byte[] otherKey = "00000000000000000000000000000000".getBytes(StandardCharsets.US_ASCII);
        String code = Totp.generate(otherKey, CURRENT_COUNTER, 6);

        assertThat(Totp.verify(KEY_SHA256, code, CURRENT_COUNTER, -1L, 6)).isEmpty();
    }

    private static String code(long counter) {
        return Totp.generate(KEY_SHA256, counter, 6);
    }
}
