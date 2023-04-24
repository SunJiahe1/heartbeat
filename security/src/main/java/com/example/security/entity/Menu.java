package com.example.security.entity;

import java.util.List;

public class Menu {
    private Integer id;
    private String pattern;
    private List<Role> roles;

    public Integer getId() {
        return id;
    }

    public String getPattern() {
        return pattern;
    }

    public List<Role> getRoles() {
        return roles;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }
}
