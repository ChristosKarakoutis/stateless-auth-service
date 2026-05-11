package com.example.authenticationsystem.util;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtil {

    public ResponseCookie createAccessTokenCookie(String token, long duration) {
        return ResponseCookie.from("jwt_access_token", token)
                .httpOnly(true)
                .secure(true) // Set to true in production (requires HTTPS)
                .path("/")
                .maxAge(duration)
                .sameSite("Strict")
                .build();
    }

    public ResponseCookie createRefreshTokenCookie(String token, long duration) {
        return ResponseCookie.from("jwt_refresh_token", token)
                .httpOnly(true)
                .secure(true)
                .path("/api/auth/refresh")
                .maxAge(duration)
                .sameSite("Strict")
                .build();
    }

    public ResponseCookie deleteAccessTokenCookie() {
        return ResponseCookie.from("jwt_access_token", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(0)
                .sameSite("Strict")
                .build();
    }

    public ResponseCookie deleteRefreshTokenCookie() {
        return ResponseCookie.from("jwt_refresh_token", "")
                .httpOnly(true)
                .secure(true)
                .path("/api/auth/refresh")
                .maxAge(0)
                .sameSite("Strict")
                .build();
    }
}
