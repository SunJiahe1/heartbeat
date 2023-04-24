package com.example.security.config;

import com.example.security.dao.MenuMapper;
import com.example.security.entity.Menu;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;
import java.util.List;

/**
 * 客户权限元数据来源
 */
@Component
public class CustomerSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    private final MenuMapper menuMapper;

    @Autowired
    public CustomerSecurityMetadataSource(MenuMapper menuMapper) {
        this.menuMapper = menuMapper;
    }

    AntPathMatcher antPathMatcher = new AntPathMatcher();

    // 自定义动态资源权限元数据信息
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        // 当前请求对象
        String requestURL = ((FilterInvocation) object).getRequest().getRequestURI();
        // 获取所有路径菜单
        List<Menu> allMenu = menuMapper.getAllMenu();
        // 遍历路径菜单，获取当前路径所需角色
        for (Menu menu : allMenu) {
            if (antPathMatcher.match(menu.getPattern(), requestURL)) {
                String[] roles = menu.getRoles().stream().map(r -> r.getName()).toArray(String[]::new);
                return SecurityConfig.createList(roles);
            }
        }
        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}
