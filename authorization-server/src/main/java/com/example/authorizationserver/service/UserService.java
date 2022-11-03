package com.example.authorizationserver.service;

import com.example.authorizationserver.model.User;

import java.util.List;

public interface UserService {
    User save(User user);
    List<User> findAll();
}
