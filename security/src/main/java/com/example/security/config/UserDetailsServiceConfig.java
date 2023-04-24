package com.example.security.config;

import com.example.security.dao.UserDao;
import com.example.security.entity.Role;
import com.example.security.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import java.util.List;

/**
 * 自定义 UserDetailsService，数据库实现（以及用户密码自更新编码）
 */
@Component
public class UserDetailsServiceConfig implements UserDetailsService, UserDetailsPasswordService {

    private final UserDao userDao;

    @Autowired
    public UserDetailsServiceConfig(UserDao userDao) {
        this.userDao = userDao;
    }

    // 加载用户
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 查询用户
        User user = userDao.loadUserByUsername(username);
        if (ObjectUtils.isEmpty(user)) throw new UsernameNotFoundException("用户名不存在~");

        // 查询权限信息
        List<Role> roles = userDao.getRolesByUid(user.getId());
        user.setRoles(roles);
        return user;
    }

    // 自动更新用户密码编码方式
    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        Integer result = userDao.updatePassword(user.getUsername(), newPassword);
        if (result == 1) {
            ((User) user).setPassword(newPassword);
        }

        return user;
    }
}
