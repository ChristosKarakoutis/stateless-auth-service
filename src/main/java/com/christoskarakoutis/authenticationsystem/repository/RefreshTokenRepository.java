package com.christoskarakoutis.authenticationsystem.repository;

import com.christoskarakoutis.authenticationsystem.entity.RefreshToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from RefreshToken r where r.token = :token")
    Optional<RefreshToken> findByTokenForUpdate(@Param("token") String token);

    @Modifying
    @Transactional
    void deleteByUserId(String userId);

    @Modifying
    @Transactional
    void deleteByToken(String token);

    @Modifying
    @Query("delete from RefreshToken r where r.expiryDate < :cutoff")
    int deleteAllExpiredBefore(@Param("cutoff") Instant cutoff);
}
