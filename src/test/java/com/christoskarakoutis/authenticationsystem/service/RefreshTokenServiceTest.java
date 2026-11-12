package com.christoskarakoutis.authenticationsystem.service;

import com.christoskarakoutis.authenticationsystem.config.JwtProperties;
import com.christoskarakoutis.authenticationsystem.entity.RefreshToken;
import com.christoskarakoutis.authenticationsystem.entity.User;
import com.christoskarakoutis.authenticationsystem.exception.TokenExpiredException;
import com.christoskarakoutis.authenticationsystem.exception.TokenRefreshException;
import com.christoskarakoutis.authenticationsystem.repository.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    private RefreshTokenService refreshTokenService;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties(
                null, null, Duration.ofMinutes(15), Duration.ofDays(7));
        refreshTokenService = new RefreshTokenService(refreshTokenRepository, properties);
    }

    private User createUser() {
        return User.builder()
                .id("user-1")
                .email("test@test.com")
                .passwordHash("hash")
                .build();
    }

    private RefreshToken createValidToken() {
        return RefreshToken.builder()
                .id(1L)
                .token("valid-token")
                .user(createUser())
                .expiryDate(Instant.now().plusSeconds(3600))
                .revoked(false)
                .build();
    }

    @Test
    void createRefreshToken_savesAndReturnsToken() {
        User user = createUser();
        when(refreshTokenRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        RefreshToken result = refreshTokenService.createRefreshToken(user);

        assertThat(result.getUser()).isEqualTo(user);
        assertThat(result.getToken()).isNotNull();
        assertThat(result.isRevoked()).isFalse();
        verify(refreshTokenRepository).save(any());
    }

    @Test
    void verifyExpiration_throwsWhenRevoked() {
        RefreshToken token = createValidToken();
        token.setRevoked(true);

        assertThatThrownBy(() -> refreshTokenService.verifyExpiration(token))
                .isInstanceOf(TokenRefreshException.class)
                .hasMessageContaining("revoked");
    }

    @Test
    void verifyExpiration_throwsWhenExpired() {
        RefreshToken token = createValidToken();
        token.setExpiryDate(Instant.now().minusSeconds(1));

        assertThatThrownBy(() -> refreshTokenService.verifyExpiration(token))
                .isInstanceOf(TokenExpiredException.class)
                .hasMessageContaining("expired");

        verify(refreshTokenRepository).delete(token);
    }

    @Test
    void verifyExpiration_returnsTokenWhenValid() {
        RefreshToken token = createValidToken();

        RefreshToken result = refreshTokenService.verifyExpiration(token);

        assertThat(result).isEqualTo(token);
        verify(refreshTokenRepository, never()).delete(any());
    }

    @Test
    void findByToken_returnsToken() {
        RefreshToken token = createValidToken();
        when(refreshTokenRepository.findByToken("valid-token")).thenReturn(Optional.of(token));

        Optional<RefreshToken> result = refreshTokenService.findByToken("valid-token");

        assertThat(result).isPresent();
        assertThat(result.get().getToken()).isEqualTo("valid-token");
    }

    @Test
    void findByToken_returnsEmptyWhenNotFound() {
        when(refreshTokenRepository.findByToken("unknown")).thenReturn(Optional.empty());

        Optional<RefreshToken> result = refreshTokenService.findByToken("unknown");

        assertThat(result).isEmpty();
    }

    @Test
    void deleteByUserId_delegatesToRepository() {
        refreshTokenService.deleteByUserId("user-1");

        verify(refreshTokenRepository).deleteByUserId("user-1");
    }

    @Test
    void deleteByToken_delegatesToRepository() {
        refreshTokenService.deleteByToken("some-token");

        verify(refreshTokenRepository).deleteByToken("some-token");
    }
}
