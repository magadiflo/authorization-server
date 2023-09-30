package com.magadiflo.authorization.server.app.services.impl;

import com.magadiflo.authorization.server.app.dtos.CreateUserDTO;
import com.magadiflo.authorization.server.app.dtos.MessageDTO;
import com.magadiflo.authorization.server.app.entities.User;
import com.magadiflo.authorization.server.app.entities.Role;
import com.magadiflo.authorization.server.app.enums.RoleName;
import com.magadiflo.authorization.server.app.repositories.IRoleRepository;
import com.magadiflo.authorization.server.app.repositories.IUserRepository;
import com.magadiflo.authorization.server.app.services.IUserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserServiceImpl implements IUserService {

    private final IUserRepository userRepository;
    private final IRoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public MessageDTO createUser(CreateUserDTO dto) {
        Set<Role> roles = dto.roles().stream()
                .map(RoleName::valueOf)
                .map(roleName -> this.roleRepository.findByRole(roleName)
                        .orElseThrow(() -> new RuntimeException("Role no encontrado")))
                .collect(Collectors.toSet());

        User user = User.builder()
                .username(dto.username())
                .password(this.passwordEncoder.encode(dto.password()))
                .roles(roles)
                .build();

        this.userRepository.save(user);

        return new MessageDTO(String.format("Usuario %s guardado", user.getUsername()));
    }
}
