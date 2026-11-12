package com.christoskarakoutis.authenticationsystem.job;

import com.christoskarakoutis.authenticationsystem.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenCleanupJob {

    private final RefreshTokenService refreshTokenService;

    @Scheduled(cron = "0 0 3 * * *", zone = "UTC")
    public void purgeExpiredTokens() {
        int deleted = refreshTokenService.purgeExpiredTokens();
        if (deleted > 0) {
            log.info("Purged {} expired refresh tokens", deleted);
        }
    }
}
