package com.example.authenticationsystem.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CookieUtilTest {

    private final CookieUtil cookieUtil = new CookieUtil();

    @Test
    @DisplayName("access token cookie has correct security attributes")
    void createAccessTokenCookie_hasCorrectAttributes() {
        var cookie = cookieUtil.createAccessTokenCookie("token123", 900);

        assertThat(cookie.getName()).isEqualTo("jwt_access_token");
        assertThat(cookie.getValue()).isEqualTo("token123");
        assertThat(cookie.getMaxAge().getSeconds()).isEqualTo(900);
        assertThat(cookie.getPath()).isEqualTo("/");
    }

    @Test
    @DisplayName("refresh token cookie is scoped to refresh endpoint")
    void createRefreshTokenCookie_hasCorrectPath() {
        var cookie = cookieUtil.createRefreshTokenCookie("refresh123", 604800);

        assertThat(cookie.getName()).isEqualTo("jwt_refresh_token");
        assertThat(cookie.getPath()).isEqualTo("/api/auth/refresh");
        assertThat(cookie.getMaxAge().getSeconds()).isEqualTo(604800);
    }

    @Test
    @DisplayName("deleting access token cookie sets max age to zero")
    void deleteAccessTokenCookie_setsMaxAgeToZero() {
        var cookie = cookieUtil.deleteAccessTokenCookie();

        assertThat(cookie.getValue()).isEmpty();
        assertThat(cookie.getMaxAge().getSeconds()).isZero();
    }

    @Test
    @DisplayName("deleting refresh token cookie sets max age to zero")
    void deleteRefreshTokenCookie_setsMaxAgeToZero() {
        var cookie = cookieUtil.deleteRefreshTokenCookie();

        assertThat(cookie.getValue()).isEmpty();
        assertThat(cookie.getMaxAge().getSeconds()).isZero();
    }
}
