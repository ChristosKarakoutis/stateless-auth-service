package com.christoskarakoutis.authenticationsystem.security;

import com.christoskarakoutis.authenticationsystem.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * Spring Security principal. getUsername() is the login identifier (email),
 * while username() is the display name.
 */
public record SecurityUser(
        String id,
        String username,
        String email,
        String passwordHash
) implements UserDetails {

    public static SecurityUser from(User user) {
        return new SecurityUser(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPasswordHash()
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
