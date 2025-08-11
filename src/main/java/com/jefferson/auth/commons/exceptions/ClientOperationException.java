package com.jefferson.auth.commons.exceptions;

public class ClientOperationException extends RuntimeException {
    public ClientOperationException(String message) {
        super(message);
    }

    public ClientOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}
