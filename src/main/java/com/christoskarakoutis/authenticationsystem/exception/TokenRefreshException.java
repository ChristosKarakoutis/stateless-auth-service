package com.christoskarakoutis.authenticationsystem.exception;

public class TokenRefreshException extends RuntimeException{
    public TokenRefreshException(String message) {
        super(message);
    }
}
