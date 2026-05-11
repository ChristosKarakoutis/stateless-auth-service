package com.example.authenticationsystem.controller;

import com.example.authenticationsystem.dto.LoginRequest;
import com.example.authenticationsystem.dto.LoginResponse;
import com.example.authenticationsystem.dto.RegisterRequest;
import com.example.authenticationsystem.dto.RegisterResponse;
import com.example.authenticationsystem.service.UserService;
import com.example.authenticationsystem.util.CookieUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AuthControllerTest {

    private MockMvc mockMvc;

    private UserService userService;
    private CookieUtil cookieUtil;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        userService = mock(UserService.class);
        cookieUtil = mock(CookieUtil.class);
        objectMapper = new ObjectMapper();
        var controller = new AuthController(userService, cookieUtil);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    // ── Register ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /api/auth/register returns 201 with user data")
    void register_returns201() throws Exception {
        var request = new RegisterRequest("user", "user@test.com", "password123");
        var response = new RegisterResponse("id-1", "user", "user@test.com");

        when(userService.registerUser(request)).thenReturn(response);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value("id-1"))
                .andExpect(jsonPath("$.email").value("user@test.com"));
    }

    // ── Login ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /api/auth/login returns 200 with Set-Cookie and user body")
    void login_setsCookiesAndReturnsUser() throws Exception {
        var request = new LoginRequest("user@test.com", "password123");
        var loginResponse = LoginResponse.builder()
                .id("id-1")
                .username("user")
                .email("user@test.com")
                .accessToken("access-token")
                .refreshToken("refresh-token")
                .build();

        var accessCookie = ResponseCookie.from("jwt_access_token", "access-token")
                .httpOnly(true).secure(true).path("/").maxAge(900).sameSite("Strict").build();
        var refreshCookie = ResponseCookie.from("jwt_refresh_token", "refresh-token")
                .httpOnly(true).secure(true).path("/api/auth/refresh").maxAge(604800).sameSite("Strict").build();

        when(userService.login(request)).thenReturn(loginResponse);
        when(cookieUtil.createAccessTokenCookie("access-token", 900)).thenReturn(accessCookie);
        when(cookieUtil.createRefreshTokenCookie("refresh-token", 604800)).thenReturn(refreshCookie);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(header().exists(HttpHeaders.SET_COOKIE))
                .andExpect(jsonPath("$.id").value("id-1"))
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(jsonPath("$.refreshToken").doesNotExist());
    }

    // ── Refresh ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /api/auth/refresh returns 200 with new cookies")
    void refresh_returnsNewCookies() throws Exception {
        var loginResponse = LoginResponse.builder()
                .id("id-1")
                .username("user")
                .email("user@test.com")
                .accessToken("new-access")
                .refreshToken("new-refresh")
                .build();

        var accessCookie = ResponseCookie.from("jwt_access_token", "new-access")
                .httpOnly(true).secure(true).path("/").maxAge(900).sameSite("Strict").build();
        var refreshCookie = ResponseCookie.from("jwt_refresh_token", "new-refresh")
                .httpOnly(true).secure(true).path("/api/auth/refresh").maxAge(604800).sameSite("Strict").build();

        when(userService.refreshToken("valid-refresh-token")).thenReturn(loginResponse);
        when(cookieUtil.createAccessTokenCookie("new-access", 900)).thenReturn(accessCookie);
        when(cookieUtil.createRefreshTokenCookie("new-refresh", 604800)).thenReturn(refreshCookie);

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("jwt_refresh_token", "valid-refresh-token")))
                .andExpect(status().isOk())
                .andExpect(header().exists(HttpHeaders.SET_COOKIE));
    }

    @Test
    @DisplayName("POST /api/auth/refresh returns 401 when no cookie")
    void refresh_returns401WhenNoCookie() throws Exception {
        mockMvc.perform(post("/api/auth/refresh"))
                .andExpect(status().isUnauthorized());
    }

    // ── Logout ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /api/auth/logout returns 200 with clearing cookies")
    void logout_clearsCookies() throws Exception {
        var deleteAccess = ResponseCookie.from("jwt_access_token", "")
                .httpOnly(true).secure(true).path("/").maxAge(0).sameSite("Strict").build();
        var deleteRefresh = ResponseCookie.from("jwt_refresh_token", "")
                .httpOnly(true).secure(true).path("/api/auth/refresh").maxAge(0).sameSite("Strict").build();

        when(cookieUtil.deleteAccessTokenCookie()).thenReturn(deleteAccess);
        when(cookieUtil.deleteRefreshTokenCookie()).thenReturn(deleteRefresh);

        mockMvc.perform(post("/api/auth/logout"))
                .andExpect(status().isOk())
                .andExpect(header().exists(HttpHeaders.SET_COOKIE));
    }
}
