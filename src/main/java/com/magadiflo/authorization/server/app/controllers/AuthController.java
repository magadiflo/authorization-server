package com.magadiflo.authorization.server.app.controllers;

import com.magadiflo.authorization.server.app.dtos.CreateUserDTO;
import com.magadiflo.authorization.server.app.dtos.MessageDTO;
import com.magadiflo.authorization.server.app.services.IUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
@RequestMapping(path = "/api/v1/auth")
public class AuthController {

    private final IUserService userService;

    @PostMapping
    public ResponseEntity<MessageDTO> createUser(@RequestBody CreateUserDTO dto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(this.userService.createUser(dto));
    }
}
