package com.christoskarakoutis.authenticationsystem.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.core.userdetails.User;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {

    private JwtService jwtService;

    @BeforeEach
    void setUp() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        Path tempDir = Files.createTempDirectory("jwt-test");
        Path privateKeyPath = tempDir.resolve("private.pem");
        Path publicKeyPath = tempDir.resolve("public.pem");

        Files.writeString(privateKeyPath, pemEncode(keyPair.getPrivate().getEncoded(), "PRIVATE KEY"));
        Files.writeString(publicKeyPath, pemEncode(keyPair.getPublic().getEncoded(), "PUBLIC KEY"));

        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "privateKeyResource",
                new FileSystemResource(privateKeyPath.toFile()));
        ReflectionTestUtils.setField(jwtService, "publicKeyResource",
                new FileSystemResource(publicKeyPath.toFile()));
        ReflectionTestUtils.setField(jwtService, "accessTokenExpiration", 900000L);
    }

    @Test
    @DisplayName("generated access token can be parsed and contains the subject")
    void generateAccessToken_createsValidJWT() {
        var user = new User("test@test.com", "", List.of());
        String token = jwtService.generateAccessToken(user);

        assertThat(token).isNotNull();
        assertThat(jwtService.extractUsername(token)).isEqualTo("test@test.com");
    }

    @Test
    @DisplayName("user_id claim is embedded in and extractable from the token")
    void generateAccessToken_withExtraClaims_embedsUserId() {
        var user = new User("test@test.com", "", List.of());
        String token = jwtService.generateAccessToken(Map.of("user_id", "abc-123"), user);

        assertThat(jwtService.extractUserId(token)).isEqualTo("abc-123");
    }

    @Test
    @DisplayName("freshly generated token is not expired")
    void isTokenExpired_returnsFalseForValidToken() {
        var user = new User("test@test.com", "", List.of());
        String token = jwtService.generateAccessToken(user);

        assertThat(jwtService.isTokenExpired(token)).isFalse();
    }

    @Test
    @DisplayName("token signed with RS256 private key is verifiable with the public key")
    void tokenSignedWithRS256_canBeVerifiedWithPublicKey() {
        var user = new User("test@test.com", "", List.of());
        String token = jwtService.generateAccessToken(user);

        assertThat(jwtService.extractUsername(token)).isEqualTo("test@test.com");
    }

    private String pemEncode(byte[] der, String label) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
    }
}
