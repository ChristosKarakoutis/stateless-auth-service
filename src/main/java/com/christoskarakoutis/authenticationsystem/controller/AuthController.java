package com.christoskarakoutis.authenticationsystem.controller;

import com.christoskarakoutis.authenticationsystem.config.JwtProperties;
import com.christoskarakoutis.authenticationsystem.dto.*;
import com.christoskarakoutis.authenticationsystem.service.AuthService;
import com.christoskarakoutis.authenticationsystem.util.CookieUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final CookieUtil cookieUtil;
    private final JwtProperties jwtProperties;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(request));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        LoginResponse res = authService.login(request);

        String accessToken = res.getAccessToken();
        String refreshToken = res.getRefreshToken();

        res.setAccessToken(null);
        res.setRefreshToken(null);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookieUtil.createAccessTokenCookie(
                        accessToken, jwtProperties.accessTokenExpiration().toSeconds()).toString())
                .header(HttpHeaders.SET_COOKIE, cookieUtil.createRefreshTokenCookie(
                        refreshToken, jwtProperties.refreshTokenExpiration().toSeconds()).toString())
                .body(res);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        authService.logout();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookieUtil.deleteAccessTokenCookie().toString())
                .header(HttpHeaders.SET_COOKIE, cookieUtil.deleteRefreshTokenCookie().toString())
                .build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@CookieValue(name = "jwt_refresh_token", required = false) String refreshToken) {
        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        LoginResponse res = authService.refreshToken(refreshToken);

        String accessToken = res.getAccessToken();
        String refreshTokenValue = res.getRefreshToken();

        res.setAccessToken(null);
        res.setRefreshToken(null);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookieUtil.createAccessTokenCookie(
                        accessToken, jwtProperties.accessTokenExpiration().toSeconds()).toString())
                .header(HttpHeaders.SET_COOKIE, cookieUtil.createRefreshTokenCookie(
                        refreshTokenValue, jwtProperties.refreshTokenExpiration().toSeconds()).toString())
                .body(res);
    }

}
