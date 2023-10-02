package com.magadiflo.authorization.server.app.controllers;

import com.magadiflo.authorization.server.app.dtos.CreateClientDTO;
import com.magadiflo.authorization.server.app.dtos.MessageDTO;
import com.magadiflo.authorization.server.app.services.IClientService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping(path = "/api/v1/clients")
public class ClientController {

    private final IClientService clientService;

    @PostMapping
    public ResponseEntity<MessageDTO> create(@RequestBody CreateClientDTO dto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(this.clientService.create(dto));
    }

}
