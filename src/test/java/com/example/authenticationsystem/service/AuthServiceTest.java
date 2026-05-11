package com.example.authenticationsystem.service;

import com.example.authenticationsystem.dto.LoginRequest;
import com.example.authenticationsystem.dto.RegisterRequest;
import com.example.authenticationsystem.dto.RegisterResponse;
import com.example.authenticationsystem.entity.RefreshToken;
import com.example.authenticationsystem.entity.User;
import com.example.authenticationsystem.exception.TokenRefreshException;
import com.example.authenticationsystem.exception.UserAlreadyExistsException;
import com.example.authenticationsystem.jwt.JwtService;
import com.example.authenticationsystem.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private AuthService authService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id("user-1")
                .username("testuser")
                .email("test@test.com")
                .passwordHash("encoded-hash")
                .build();
    }

    // ── Register ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("register creates user and returns response")
    void registerUser_success() {
        var request = new RegisterRequest("testuser", "test@test.com", "password123");
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("test@test.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("password123")).thenReturn("encoded-hash");
        when(userRepository.save(any())).thenAnswer(i -> {
            User u = i.getArgument(0);
            u.setId("new-id");
            return u;
        });

        RegisterResponse response = authService.registerUser(request);

        assertThat(response.getId()).isEqualTo("new-id");
        assertThat(response.getUsername()).isEqualTo("test@test.com");
        assertThat(response.getEmail()).isEqualTo("test@test.com");
    }

    @Test
    @DisplayName("register throws when username is taken")
    void registerUser_throwsWhenUsernameTaken() {
        var request = new RegisterRequest("testuser", "test@test.com", "password123");
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        assertThatThrownBy(() -> authService.registerUser(request))
                .isInstanceOf(UserAlreadyExistsException.class)
                .hasMessageContaining("Username");
    }

    @Test
    @DisplayName("register throws when email is taken")
    void registerUser_throwsWhenEmailTaken() {
        var request = new RegisterRequest("testuser", "test@test.com", "password123");
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("test@test.com")).thenReturn(Optional.of(testUser));

        assertThatThrownBy(() -> authService.registerUser(request))
                .isInstanceOf(UserAlreadyExistsException.class)
                .hasMessageContaining("Email");
    }

    // ── Login ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("login returns tokens for valid credentials")
    void login_success() {
        var request = new LoginRequest("test@test.com", "password123");
        when(userRepository.findByEmail("test@test.com")).thenReturn(Optional.of(testUser));
        when(jwtService.generateAccessToken(any(), any())).thenReturn("access-token");

        var refreshToken = RefreshToken.builder()
                .token("refresh-token")
                .user(testUser)
                .expiryDate(Instant.now().plusSeconds(3600))
                .build();
        when(refreshTokenService.createRefreshToken(testUser)).thenReturn(refreshToken);

        var response = authService.login(request);

        assertThat(response.getId()).isEqualTo("user-1");
        assertThat(response.getAccessToken()).isEqualTo("access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
        verify(authenticationManager).authenticate(any());
    }

    @Test
    @DisplayName("login throws BadCredentialsException on wrong password")
    void login_throwsOnBadPassword() {
        var request = new LoginRequest("test@test.com", "wrong");
        doThrow(new BadCredentialsException("Bad credentials"))
                .when(authenticationManager).authenticate(any());

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(BadCredentialsException.class);
    }

    // ── Logout ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("logout deletes refresh tokens and clears context")
    void logout_deletesTokensAndClearsContext() {
        Authentication auth = mock(Authentication.class);
        when(auth.getDetails()).thenReturn("user-1");
        SecurityContextHolder.getContext().setAuthentication(auth);

        authService.logout();

        verify(refreshTokenService).deleteByUserId("user-1");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    // ── Refresh ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("refresh returns new token pair for valid token")
    void refreshToken_success() {
        var storedToken = RefreshToken.builder()
                .token("old-refresh")
                .user(testUser)
                .expiryDate(Instant.now().plusSeconds(3600))
                .revoked(false)
                .build();

        var newRefreshToken = RefreshToken.builder()
                .token("new-refresh")
                .user(testUser)
                .expiryDate(Instant.now().plusSeconds(3600))
                .build();

        when(refreshTokenService.findByToken("old-refresh")).thenReturn(Optional.of(storedToken));
        when(refreshTokenService.verifyExpiration(storedToken)).thenReturn(storedToken);
        when(jwtService.generateAccessToken(any(), any())).thenReturn("new-access");
        when(refreshTokenService.createRefreshToken(testUser)).thenReturn(newRefreshToken);

        var response = authService.refreshToken("old-refresh");

        assertThat(response.getAccessToken()).isEqualTo("new-access");
        assertThat(response.getRefreshToken()).isEqualTo("new-refresh");
        verify(refreshTokenService).deleteByToken("old-refresh");
    }

    @Test
    @DisplayName("refresh throws when token is not in database")
    void refreshToken_throwsWhenTokenNotFound() {
        when(refreshTokenService.findByToken("invalid")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refreshToken("invalid"))
                .isInstanceOf(TokenRefreshException.class)
                .hasMessageContaining("not in database");
    }
}
