package com.magadiflo.authorization.server.app;

import com.magadiflo.authorization.server.app.entities.Role;
import com.magadiflo.authorization.server.app.enums.RoleName;
import com.magadiflo.authorization.server.app.repositories.IRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.List;

@RequiredArgsConstructor
@SpringBootApplication
public class MainApplication {

    private final IRoleRepository roleRepository;

    public static void main(String[] args) {
        SpringApplication.run(MainApplication.class, args);
    }

    @Bean
    public CommandLineRunner run() {
        return args -> {
            Role adminRole = Role.builder().role(RoleName.ROLE_ADMIN).build();
            Role userRole = Role.builder().role(RoleName.ROLE_USER).build();
//            this.roleRepository.saveAll(List.of(adminRole, userRole));
        };
    }

}
