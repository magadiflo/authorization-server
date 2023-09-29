# [Spring Boot 3 - OAuth2.0 Authorization Server y Resource Server - Angular](https://www.youtube.com/playlist?list=PL4bT56Uw3S4zqmhhzJdsA_8aNhttF3mWa)

- Tutorial tomado del canal de youtube de **Luigi Code**.
- Documentación oficial
  [Spring Authorization Server Reference](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/getting-started.html)

---

## Configuraciones iniciales

Se muestran las dependencias que se usarán para nuestro proyecto **Authorization Server**:

````xml
<!--Spring Boot 3.1.4-->
<!--Java 17-->
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-authorization-server</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
````

Agregamos algunas configuraciones en el **application.yml**. Nuestro Authorization Server estará corriendo en el
puerto **9000** y adicionalmente agregamos dos configuraciones **TRACE** para que nos muestre información en consola:

````yaml
server:
  port: 9000

logging:
  level:
    org.springframework.security: trace
    org.springframework.security.oauth2: trace
````

## Componentes mínimos para un Authorization Server

Empezaremos creando una clase de configuración relacionada con el usuario. Por el momento registraremos a nuestro
usuario en memoria y utilizaremos `{noop}` junto a su contraseña para trabajarlo como texto plano. Más adelante,
haremos uso de un `PasswordEncoder`:

````java

@Configuration
public class UserManagementConfig {
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("user")
                .password("{noop}12345")
                .authorities("ROLE_USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
````
