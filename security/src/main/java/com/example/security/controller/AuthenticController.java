package com.example.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/all") // 拦截器实现
@CrossOrigin // 代表类中所有方法都允许跨域请求  springmvc 注解解决方案
public class AuthenticController {
    @GetMapping("/authentic")
    // @CrossOrigin(origins = {"http://127.0.0.1:63342"}) // 允许跨域的请求
    // @CrossOrigin // 此方法所有跨域请求都被允许
    public String authentic() {
        System.out.println("Authentic");

        // 获取认证信息
        // 配置安全策略(默认只有请求线程才能访问)
        // SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("身份信息: " + authentication.getPrincipal());
        System.out.println("权限信息: " + authentication.getAuthorities());

        new Thread(() -> {
            Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
            System.out.println("子线程获取: " +  authentication1);
        }).start();

        return "Authentic";
    }

    @GetMapping("/authenticFailure")
    public String authenticFailure() {
        System.out.println("AuthenticFailure");
        return "AuthenticFailure";
    }
}
