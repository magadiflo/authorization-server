package com.magadiflo.authorization.server.app.federated;

import com.magadiflo.authorization.server.app.entities.GoogleUser;
import com.magadiflo.authorization.server.app.repositories.IGoogleUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.function.Consumer;

@Slf4j
@RequiredArgsConstructor
public final class UserRepositoryOAuth2UserHandler implements Consumer<OAuth2User> {

    private final IGoogleUserRepository googleUserRepository;

    @Override
    public void accept(OAuth2User user) {
        // Capturar el usuario en una base de datos en la primera autenticación
        if (this.googleUserRepository.findByEmail(user.getName()).isEmpty()) {
            StringBuilder sb = new StringBuilder("Guardando usuario de Google por primera vez: ")
                    .append("name: ").append(user.getName())
                    .append(", claims: ").append(user.getAttributes())
                    .append(", authorities: ").append(user.getAuthorities());
            System.out.println(sb);
            GoogleUser googleUser = GoogleUser.fromOauth2User(user);
            log.info("googleUser: {}", googleUser);
            this.googleUserRepository.save(googleUser);
        } else {
            log.info(":::::: Bienvenido {} ::::::", user.getAttributes().get("given_name"));
        }
    }
}
