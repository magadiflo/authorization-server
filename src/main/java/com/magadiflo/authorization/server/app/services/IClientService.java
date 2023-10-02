package com.magadiflo.authorization.server.app.services;

import com.magadiflo.authorization.server.app.dtos.CreateClientDTO;
import com.magadiflo.authorization.server.app.dtos.MessageDTO;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

public interface IClientService extends RegisteredClientRepository {
    MessageDTO create(CreateClientDTO dto);
}
