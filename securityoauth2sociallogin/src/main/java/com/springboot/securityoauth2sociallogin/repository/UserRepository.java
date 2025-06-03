package com.springboot.securityoauth2sociallogin.repository;

import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Repository;

import com.springboot.securityoauth2sociallogin.model.users.User;

@Repository
public class UserRepository {

    private Map<String, Object> users = new HashMap<String, Object>();

    public User findByUsername(String username) {
        if (users.containsKey(username)) {
            return (User) users.get(username);
        }
        return null;
    }

    public void register(User user) {
        if (users.containsKey(user.getUsername())) {
            return;
        }
        users.put(user.getUsername(), user);
    }
}