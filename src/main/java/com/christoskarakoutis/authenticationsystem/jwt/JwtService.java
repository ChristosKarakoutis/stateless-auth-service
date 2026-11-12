package com.christoskarakoutis.authenticationsystem.jwt;

import com.christoskarakoutis.authenticationsystem.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties properties;

    private PrivateKey signingKey;
    private PublicKey verificationKey;

    @PostConstruct
    void loadKeys() {
        signingKey = readPrivateKey(loadPem(properties.privateKey()));
        verificationKey = readPublicKey(loadPem(properties.publicKey()));
    }

    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(verificationKey)
                .clockSkewSeconds(30)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    public String extractUsername(String token) {
        return parse(token).getSubject();
    }

    public String extractUserId(String token) {
        return parse(token).get("user_id", String.class);
    }

    public String generateAccessToken(UserDetails userDetails) {
        return generateAccessToken(new HashMap<>(), userDetails);
    }

    public String generateAccessToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, properties.accessTokenExpiration().toMillis());
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expirationMs
    ) {
        long now = System.currentTimeMillis();
        return Jwts
                .builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(now))
                .expiration(new Date(now + expirationMs))
                .signWith(signingKey, Jwts.SIG.RS256)
                .compact();
    }

    public boolean isTokenExpired(String token) {
        return isExpired(parse(token));
    }

    private String loadPem(Resource resource) {
        try (var stream = resource.getInputStream()) {
            return new String(stream.readAllBytes());
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load key: " + resource.getFilename(), e);
        }
    }

    private PrivateKey readPrivateKey(String pem) {
        try {
            String content = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(content);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse private key", e);
        }
    }

    private PublicKey readPublicKey(String pem) {
        try {
            String content = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(content);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse public key", e);
        }
    }
}
