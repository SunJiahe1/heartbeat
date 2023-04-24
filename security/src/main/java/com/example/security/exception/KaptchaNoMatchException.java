package com.example.security.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * 自定义kaptcha异常
 */
public class KaptchaNoMatchException extends AuthenticationException {
    public KaptchaNoMatchException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public KaptchaNoMatchException(String msg) {
        super(msg);
    }
}
