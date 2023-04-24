package com.example.security.dao;

import com.example.security.entity.Role;
import com.example.security.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Mapper
@Repository
public interface UserDao {

    // 根据用户名返回用户
    User loadUserByUsername(String username);

    // 根据用户id查询用户角色信息
    List<Role> getRolesByUid(Integer uid);

    // 根据用户名更新密码
    Integer updatePassword(@Param("username") String username, @Param("password") String password);
}
