package com.example.security.controller;

import com.example.security.entity.Role;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import java.util.ArrayList;
import java.util.List;

@RestController
public class VipController {

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/guest")
    public String guest() {
        return "guest";
    }


    @GetMapping("/vip1")
    public String vip1() {
        return "vip1";
    }

    @PostMapping("/vip2")
    public String vip2() {
        return "vip2";
    }

    @PreAuthorize("hasRole('ADMIN') and authentication.name == 'root'") // 对请求角色进行权限判断
    @GetMapping("/a")
    public String a() {
        return "a";
    }

    @PreAuthorize("authentication.name == #name") // 对请求参数进行权限判断
    @GetMapping("/b")
    public String b(String name) {
        return name;
    }

    @PreFilter(value = "filterObject.id % 2 != 0", filterTarget = "roles") // filterTarget 必须是数组类型，对请求参数进行过滤
    @PostMapping("/c")
    public List<Role> c(@RequestBody List<Role> roles) {
        return roles;
    }

    @PostAuthorize("returnObject.toString() == 'd'") // 对返回参数进行权限判断
    @GetMapping("/d")
    public String d(String d) {
        return d;
    }

    @PostFilter("filterObject % 2 == 0") // 对返回数据进行过滤，要求数组
    @GetMapping("/e")
    public List<Integer> e(int m) {
        List<Integer> n = new ArrayList<>();
        for (int i = 0; i < m; i++) {
            n.add(i);
        }
        return n;
    }


    // 以下都不可以使用表达式


    @Secured("ROLE_USER")
    @GetMapping("/user2")
    public String user2() {
        return "User2";
    }

    @Secured({"ROLE_USER", "ROLE_ADMIN"}) // 有一个即可
    @GetMapping("/users")
    public String users() {
        return "Users";
    }



    @PermitAll // 都可以访问
    @GetMapping("permitAll")
    public String permitAll() {
        return "permitAll";
    }

    @DenyAll // 都拒绝访问
    @GetMapping("/denyAll")
    public String denyAll() {
        return "denyAll";
    }

    @RolesAllowed({"ROLE_USER", "ROLE_ADMIN"}) // 有一个即可
    @GetMapping("rolesAllowed")
    public String rolesAllowed() {
        return "rolesAllowed";
    }
}
