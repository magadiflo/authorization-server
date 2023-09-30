package com.magadiflo.authorization.server.app.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import com.magadiflo.authorization.server.app.entities.User;

import java.util.Optional;

public interface IUserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
