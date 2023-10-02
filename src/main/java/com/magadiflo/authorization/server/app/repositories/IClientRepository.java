package com.magadiflo.authorization.server.app.repositories;

import com.magadiflo.authorization.server.app.entities.Client;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IClientRepository extends JpaRepository<Client, Long> {
    Optional<Client> findByClientId(String clientId);
}
