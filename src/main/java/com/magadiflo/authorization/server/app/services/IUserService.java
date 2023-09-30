package com.magadiflo.authorization.server.app.services;

import com.magadiflo.authorization.server.app.dtos.CreateUserDTO;
import com.magadiflo.authorization.server.app.dtos.MessageDTO;

public interface IUserService {
    MessageDTO createUser(CreateUserDTO dto);
}
