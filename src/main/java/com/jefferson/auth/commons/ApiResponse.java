package com.jefferson.auth.commons;

public record ApiResponse<T>(
        int code,
        String message,
        T data
) {
    public static <T> ApiResponse<T> response(String message, T data, int code) {
        return new ApiResponse<>(code, message, data);
    }

}