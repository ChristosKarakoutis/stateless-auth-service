package com.christoskarakoutis.authenticationsystem.service;

import com.christoskarakoutis.authenticationsystem.config.JwtProperties;
import com.christoskarakoutis.authenticationsystem.entity.RefreshToken;
import com.christoskarakoutis.authenticationsystem.entity.User;
import com.christoskarakoutis.authenticationsystem.exception.TokenExpiredException;
import com.christoskarakoutis.authenticationsystem.exception.TokenRefreshException;
import com.christoskarakoutis.authenticationsystem.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties jwtProperties;

    public RefreshToken createRefreshToken(User user) {
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plus(jwtProperties.refreshTokenExpiration()))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Must run inside the refresh transaction. The row lock is held until that
     * transaction commits, so a concurrent refresh of the same token blocks,
     * then re-reads and finds the row already deleted.
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public Optional<RefreshToken> findByTokenForUpdate(String token) {
        return refreshTokenRepository.findByTokenForUpdate(token);
    }

    @Transactional
    public void deleteByUserId(String userId) {
        refreshTokenRepository.deleteByUserId(userId);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.isRevoked()) {
            throw new TokenRefreshException("Refresh token has been revoked.");
        }

        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            throw new TokenExpiredException("Refresh token was expired. Please make a new sign in request.");
        }
        return token;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public void deleteByToken(String token) {
        refreshTokenRepository.deleteByToken(token);
    }

    @Transactional
    public int purgeExpiredTokens() {
        return refreshTokenRepository.deleteAllExpiredBefore(Instant.now());
    }
}
