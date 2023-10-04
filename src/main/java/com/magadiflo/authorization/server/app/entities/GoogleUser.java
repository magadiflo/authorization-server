package com.magadiflo.authorization.server.app.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.user.OAuth2User;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
@Entity
@Table(name = "google_users")
public class GoogleUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String email;
    private String name;
    private String givenName;
    private String familyName;
    private String pictureUrl;

    public static GoogleUser fromOauth2User(OAuth2User oAuth2User) {
        return GoogleUser.builder()
                .email(oAuth2User.getName())
                .name(oAuth2User.getAttribute("name").toString())
                .givenName(oAuth2User.getAttribute("given_name").toString())
                .familyName(oAuth2User.getAttribute("family_name").toString())
                .pictureUrl(oAuth2User.getAttribute("picture").toString())
                .build();
    }

}
