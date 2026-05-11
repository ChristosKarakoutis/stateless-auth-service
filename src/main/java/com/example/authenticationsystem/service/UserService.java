package com.example.authenticationsystem.service;

import com.example.authenticationsystem.dto.LoginRequest;
import com.example.authenticationsystem.dto.LoginResponse;
import com.example.authenticationsystem.dto.RegisterRequest;
import com.example.authenticationsystem.dto.RegisterResponse;
import com.example.authenticationsystem.entity.RefreshToken;
import com.example.authenticationsystem.entity.User;
import com.example.authenticationsystem.exception.TokenRefreshException;
import com.example.authenticationsystem.exception.UserAlreadyExistsException;
import com.example.authenticationsystem.jwt.JwtService;
import com.example.authenticationsystem.repository.UserRepository;
import lombok.RequiredArgsConstructor;

import java.util.Map;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor

public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;

    public RegisterResponse registerUser(RegisterRequest request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new UserAlreadyExistsException("Username is already in use.");
        }
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new UserAlreadyExistsException("Email is already in use.");
        }
        String passwordHash = passwordEncoder.encode(request.getPassword());
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .passwordHash(passwordHash)
                .build();

        User savedUser = userRepository.save(user);
        return new RegisterResponse(
                savedUser.getId(),
                savedUser.getUsername(),
                savedUser.getEmail()
        );
    }

    public LoginResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found."));

        String accessToken = jwtService.generateAccessToken(Map.of("user_id", user.getId()), user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return LoginResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .build();
    }

    public void logout() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String userId = (String) auth.getDetails();

        refreshTokenService.deleteByUserId(userId);

        SecurityContextHolder.clearContext();
    }

    @Transactional
    public LoginResponse refreshToken(String token) {
        RefreshToken storedToken = refreshTokenService.findByToken(token)
                .orElseThrow(() -> new TokenRefreshException("Refresh token is not in database!"));

        RefreshToken verifiedToken = refreshTokenService.verifyExpiration(storedToken);
        User user = verifiedToken.getUser();

        String accessToken = jwtService.generateAccessToken(Map.of("user_id", user.getId()), user);
        refreshTokenService.deleteByToken(token);
        RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);

        return LoginResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .accessToken(accessToken)
                .refreshToken(newRefreshToken.getToken())
                .build();
    }

}
