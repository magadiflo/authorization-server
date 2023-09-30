package com.magadiflo.authorization.server.app.repositories;

import com.magadiflo.authorization.server.app.entities.Role;
import com.magadiflo.authorization.server.app.enums.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IRoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRole(RoleName roleName);
}
