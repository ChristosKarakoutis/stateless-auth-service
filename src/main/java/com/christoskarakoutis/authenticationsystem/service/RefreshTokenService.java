package com.christoskarakoutis.authenticationsystem.service;

import com.christoskarakoutis.authenticationsystem.entity.RefreshToken;
import com.christoskarakoutis.authenticationsystem.entity.User;
import com.christoskarakoutis.authenticationsystem.exception.TokenExpiredException;
import com.christoskarakoutis.authenticationsystem.exception.TokenRefreshException;
import com.christoskarakoutis.authenticationsystem.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${security.jwt.refresh-token-expiration}")
    private long refreshTokenDurationMs;

    public RefreshToken createRefreshToken(User user) {
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public void deleteByUserId(String userId) {
        refreshTokenRepository.deleteByUserId(userId);
    }
    
    public RefreshToken verifyExpiration(RefreshToken token) {
        if(token.isRevoked()) {
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
    public void deleteByToken(String token) { refreshTokenRepository.deleteByToken(token);}
}
