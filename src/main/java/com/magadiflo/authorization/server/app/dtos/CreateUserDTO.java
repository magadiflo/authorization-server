package com.magadiflo.authorization.server.app.dtos;

import java.util.List;

public record CreateUserDTO(String username, String password, List<String> roles) {
}
