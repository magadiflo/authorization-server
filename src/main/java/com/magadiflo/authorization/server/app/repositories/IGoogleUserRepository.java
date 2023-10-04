package com.magadiflo.authorization.server.app.repositories;

import com.magadiflo.authorization.server.app.entities.GoogleUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IGoogleUserRepository extends JpaRepository<GoogleUser, Long> {
    Optional<GoogleUser> findByEmail(String email);
}
