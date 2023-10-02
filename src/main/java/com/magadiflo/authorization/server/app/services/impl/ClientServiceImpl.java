package com.magadiflo.authorization.server.app.services.impl;

import com.magadiflo.authorization.server.app.dtos.CreateClientDTO;
import com.magadiflo.authorization.server.app.dtos.MessageDTO;
import com.magadiflo.authorization.server.app.entities.Client;
import com.magadiflo.authorization.server.app.repositories.IClientRepository;
import com.magadiflo.authorization.server.app.services.IClientService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Slf4j
@Service
public class ClientServiceImpl implements IClientService {

    private final IClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public MessageDTO create(CreateClientDTO dto) {
        Client client = this.clientFromDto(dto);
        this.clientRepository.save(client);
        return new MessageDTO(String.format("Cliente %s registrado", client.getClientId()));
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        // No usamos este save(...), creamos nuestro propio método create() para registrar al cliente en la BD
    }

    @Override
    public RegisteredClient findById(String id) {
        return this.findClientByClientId(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return this.findClientByClientId(clientId);
    }

    private RegisteredClient findClientByClientId(String clientId) {
        return this.clientRepository.findByClientId(clientId)
                .map(Client::toRegisteredClient)
                .orElseThrow(() -> new RuntimeException("Cliente no encontrado"));
    }

    private Client clientFromDto(CreateClientDTO dto) {
        return Client.builder()
                .clientId(dto.clientId())
                .clientSecret(this.passwordEncoder.encode(dto.clientSecret()))
                .clientAuthenticationMethods(dto.clientAuthenticationMethods())
                .authorizationGrantTypes(dto.authorizationGrantTypes())
                .redirectUris(dto.redirectUris())
                .scopes(dto.scopes())
                .requireProofKey(dto.requireProofKey())
                .build();
    }
}
