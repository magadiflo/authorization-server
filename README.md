# [Spring Boot 3 - OAuth2.0 Authorization Server y Resource Server - Angular](https://www.youtube.com/playlist?list=PL4bT56Uw3S4zqmhhzJdsA_8aNhttF3mWa)

- Tutorial tomado del canal de youtube de **Luigi Code**.
- Documentación oficial
  [Spring Authorization Server Reference](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/getting-started.html)

---

# CAPÍTULO 1: Configuración mínima del Authorization Server

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

Empezaremos creando una clase de configuración `UserManagementConfig` relacionada con el usuario. Por el momento
registraremos a nuestro usuario en memoria y utilizaremos `{noop}` junto a su contraseña para trabajarlo como
texto plano. Más adelante, haremos uso de un `PasswordEncoder`:

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

Ahora, como deseamos personalizar la configuración predeterminada del servidor de autorización, crearemos la clase
de configuración `SecurityConfig` donde definiremos los componentes necesarios como un `@Bean`:

````java

@Slf4j
@EnableWebSecurity
@Configuration
public class SecurityConfig {
    //(1)
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults()); // Habilita OpenID Connect 1.0

        // Redirigir a la página del login cuando no esté autenticado desde el endpoint de autorización.
        http.exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                // Aceptar tokens de acceso para la Información del Usuario y/o el Registro del Cliente.
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));
        return http.build();
    }

    //(2)
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // Que todos los request que se hagan, deben estar previamente autenticados
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // El formulario de inicio de sesión gestiona la redirección a la página de inicio de sesión desde
                // la cadena de filtros del servidor de autorización
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    //(3)
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // withId(...), identificador que le damos al registro de este cliente
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                // Identificador de nuestra aplicación cliente (frontEnd)
                .clientId("front-end-app")
                // Clave secreta para nuestra aplicación cliente
                .clientSecret("{noop}secret-key")
                // Añade un método de autenticación que el cliente puede utilizar al autenticarse 
                // con el servidor de autorización. En nuestro caso hemos añadido el método "client_secret_basic" que
                // corresponde con el tipo "Basic Auth"
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // authorizationGrantType(...), añade un tipo de concesión de autorización que el cliente puede 
                // utilizar. En nuestro caso, hemos añadido 3 tipos de concesiones: authorization_code, refresh_token 
                // y el client_credentials. 
                // ¡Importante!, la última práctica recomendada de seguridad de OAuth 2.0 prohíbe el uso de la concesión  
                // de credenciales de contraseña de propietario de recurso (deprecated)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                // Añade un URI de redirección que el cliente puede utilizar en un flujo basado en la redirección.
                .redirectUri("https://oauthdebugger.com/debug")
                // scope(...), añade un ámbito que el cliente puede utilizar. El ámbito openid es necesario para las 
                // solicitudes de autenticación de OpenID Connect.
                .scope(OidcScopes.OPENID)
                // Establece los ajustes de configuración del cliente.
                .clientSettings(this.clientSettings())
                .build();

        return new InMemoryRegisteredClientRepository(oidcClient);
    }

    //(4)
    @Bean
    public ClientSettings clientSettings() {
        return ClientSettings.builder().requireProofKey(true).build();
    }

    //(5)
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        // issuer(...), establece la URL que el Servidor de Autorización utiliza como Identificador de Emisor.
        return AuthorizationServerSettings.builder().issuer("http://localhost:9000").build();
    }

    //(6)
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    //(7)
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRSAKey();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    //(8)
    private static RSAKey generateRSAKey() {
        KeyPair keyPair = generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    //(9)
    private static KeyPair generateKeyPair() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }
        return keyPair;
    }
}
````

**DONDE**

- `@Slf4j`, es una anotación de Lombok. Aunque por el momento no lo estamos usando en la clase, pero lo dejamos por si
  más adelante lo requerimos.
- `@EnableWebSecurity`, nos permite personalizar la configuración de seguridad de la aplicación.
- `@Configuration`, indica que es una clase de configuración donde algunos métodos serán anotados con `@Bean`.
- `(oidc) OpenID Connect`, engloba al `open id` (proceso de autenticación) + `oauth2` (proceso de autorización).
- `(1)`, una cadena de filtros de Spring Security para los endpoints del protocolo.
- `(2)`, una cadena de filtros de Spring Security para la autenticación.
- `(3)`, una instancia de `RegisteredClientRepository` para gestionar clientes. En este caso, al igual que hicimos con
  el usuario, aquí también estamos registrando un cliente de OAuth2 en memoria. Además, vemos que dentro del método
  estamos usando la dirección del sitio web `https://oauthdebugger.com/debug` como uri de redirección. Normalmente,
  aquí debería estar la dirección de nuestra aplicación de `frontEnd` quien recibirá el código generado por el servidor
  de autorización, pero como aún no lo tenemos desarrollado estamos usando la página de `oauthdebugger` para ver qué es
  lo que nos retorna el servidor de autorización y algunas cosas adicionales que veremos cuando ejecutemos la
  aplicación.
- `(4)`, `ClientSettings.builder().requireProofKey(true).build()`, establézcalo como `true` si se requiere que el
  cliente **proporcione un desafío de clave de prueba** y un **verificador** al realizar el flujo de concesión de
  `código de autorización.` Parámetros: requireProofKey - **true si el cliente debe proporcionar una clave de prueba y
  un verificador**, false en caso contrario. De esta manera, si alguien nos roba el **token** no podrá usarlo, ya que
  necesita además el `Proof Key (clave de prueba y su verificador)`.
- `(5)`, una instancia de AuthorizationServerSettings para configurar `Spring Authorization Server`.
- `(6)`, una instancia de JwtDecoder para descodificar access tokens firmados.
- `(7)`, una instancia de `com.nimbusds.jose.jwk.source.JWKSource` para firmar access tokens.
- `(8)`, `RSAKey`: clave web RSA JSON (JWK) pública y privada. Esta clase es inmutable. Proporciona RSA JWK importación
  desde / exportación a las siguientes interfaces y clases Java estándar: `RSAPublicKey, RSAPrivateKey`.
- `(9)`, `KeyPair`: un simple soporte para un par de claves (una clave pública y una clave privada). No impone ninguna
  seguridad y, cuando se inicializa, debe tratarse como una PrivateKey.

## Funcionamiento del Servidor de Autorización con los componentes mínimos configurados

Ejecutamos nuestro `Authorization Server` y entramos mediante la
url `http://localhost:9000/.well-known/oauth-authorization-server` de **nuestro servidor de autorización** y observamos
un objeto json con endpoints disponibles:

![1-endpoints-authorization-server](./assets/1-endpoints-authorization-server.png)

Lo primero que debemos hacer es obtener un `Authorization Code`. Para eso utilizaremos el **endpoint** de la imagen
anterior `"authorization_endpoint": "http://localhost:9000/oauth2/authorize"`.

Ahora, como aún no hemos desarrollado el `frontEnd` necesitamos una forma de poder obtener el código de autorización
mediante la url anterior. Para eso utilizaremos la página [oauthdebugger](https://oauthdebugger.com/debug):

![2-oauthdebugger](./assets/2-oauthdebugger.png)

En la página anterior, damos click en `Start over` y completamos los campos que se nos muestran:

![3-oauthdebugger-configure-1](./assets/3-oauthdebugger-configure-1.jpeg)

**DONDE**

1. El `authorize URI` en el servidor de autorización es donde comienza un flujo OAuth 2.0. Aquí colocaremos la url
   para obtener un `Authorization Code`.
2. El `redirect URI` indica al emisor a dónde debe redirigir el navegador cuando finalice el flujo. Aquí debemos colocar
   la url del `cliente (frontEnd)`. Por el momento, como aún no tenemos desarrollado nuestro propio `frontEnd` estamos
   usando la dirección de `oauthdebugger` que configuramos para nuestro cliente registrado en el servidor de
   autorización
3. Cada cliente (sitio web o aplicación móvil) se identifica mediante un `client id`. A diferencia del `client secret`,
   **el ID de cliente es un valor público que no es necesario proteger**. Aquí debemos colocar el client
   id: `front-end-app` que registramos para nuestro cliente.
4. Los clientes pueden solicitar información adicional o permisos mediante ámbitos. Aquí colocamos el scope `openid` que
   registramos para nuestro cliente.
5. El estado es un valor opcional que se lleva a través de todo el flujo y se devuelve al cliente. Es común utilizar el
   estado para almacenar un token anti-falsificación que puede ser verificado después de que el flujo de inicio de
   sesión se ha completado. Otro uso común es almacenar la ubicación a la que el usuario debe ser redirigido después de
   iniciar sesión. Aquí, el valor es generado automáticamente por la página `oauthdebugger`.
6. Un nonce (o número utilizado una vez) es un valor aleatorio que se utiliza para evitar ataques de repetición. Este
   valor también es generado automáticamente por la página `oauthdebugger`.
7. El `Response Type` es del tipo `authorization_code` que definimos como un `authorizationGrantType`.
8. `¿Usamos PKCE?`, sí, precisamente es por eso que colocamos en `true` el `requireProofKey(...)` dentro del
   método `ClientSettings`. Aquí además seleccionamos el `SHA-256`.
9. El `code verifier` lo necesitamos para el flujo porque usaremos el `PKCE`.
10. El `code challenge` lo necesitamos para el flujo porque usaremos el `PKCE`.
11. El `Token URI` es desde donde obtendremos el access token.

**IMPORTANTE**

> El encargado de generar el `code verifier` y el `code challenge` es el `client`, el servidor simplemente los comprueba
> pero se desentiende totalmente. Lo que sí genera el servidor obviamente es el `authorization code`.

Finalmente, en la parte inferior de la página veremos el resumen de cómo se hará el request:

![4-oauthdebugger-configure-2](./assets/4-oauthdebugger-configure-2.jpeg)

Cliqueamos en `Send Request` y obtendremos el formulario de login proporcionado por nuestro servidor de autorización:

![5-after-send-request](./assets/5-after-send-request.png)

Nos logueamos con el usuario registrado dentro del servidor de autorización:

![6-authorization-code-success](./assets/6-authorization-code-success.jpeg)

Como observamos, estamos obteniendo el `Authorization code` que solicitamos. Recordemos que en el `redirect uri`
definimos la dirección de la página de `oauthdebugger`, precisamente por esta razón, para obtener aquí el código de
autorización, al menos por el momento mientras aún no tengamos nuestra aplicación `frontEnd`.

Ahora, a partir del `Authorization Code` solicitaremos un `Access Token` y dado que el flujo se inició con un desafío de
código `PKCE`, debemos tener en cuenta eso al momento de definir los parámetros de la solicitud, es decir, dentro del
conjunto de parámetros a enviar debe estar el `code_verifier`:

````bash
curl -v -X POST -u front-end-app:secret-key -d "grant_type=authorization_code&client_id=front-end-app&redirect_uri=https://oauthdebugger.com/debug&code_verifier=cYKGgCAGUutO0B9q5kPCT16DA3JWQjqtXFFOIqTQ9Tp&code=fBY9BnOd9AABgdALk7PKucCtA6FoNN5AprDKM1rhoWUVHxihUhVqQUgYdb7-9z4GBL6oEb0AqCMTuCij0O2cjtGhRtP0OFQgrYa1a-ITtOUaKtfHDJl4R0NOezuuG7Dy" http://localhost:9000/oauth2/token | jq

> POST /oauth2/token HTTP/1.1
> Host: localhost:9000
> Authorization: Basic ZnJvbnQtZW5kLWFwcDpzZWNyZXQta2V5
> Content-Type: application/x-www-form-urlencoded
> ...
>
< HTTP/1.1 200
< Content-Type: application/json;charset=UTF-8
< ...
<
{
  "access_token": "eyJraWQiOiI4MzViZTNkOC1mZWFhLTRmZTQtOTI3YS1lMjRmNjliOGFjYTUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoiZnJvbnQtZW5kLWFwcCIsIm5iZiI6MTY5NjAwNDEzMSwic2NvcGUiOlsib3BlbmlkIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMCIsImV4cCI6MTY5NjAwNDQzMSwiaWF0IjoxNjk2MDA0MTMxfQ.geTLlNriah-75L1zPw8aLBa9vxky9hQ5UQ9_gQFsN9qZRWqOdu-PVIAQmj9NH1yULrE6cxr9ixmudpXK5t0OZgnUpvWTW_Y48jm160jT6BmGfWdTTs2upPcBnGITFImGu3BugydsuuoJ8uQEbRUWa0CY-4s9kropJ4jCmOmDe8unKEtdJ36qRAWaNAztom7PxfuaTWpURTGVwFd0-MCQwKN6FhgLN7uE-twjfCgrZkiJ16n063MfolMXSaKx7jsQfF9Dr6cGP1epKavfbiosy-AN-CrLNf_ZlZMjDh9UCzsvETf7Fv36EYY1yF5_003FzwP1HD7StIjCMhvCqcEmqw",
  "refresh_token": "JgzGIhXHlHAmEhRFpRiN11H6qKTXzCf22Wx4CNR_rxRmTG-qB-B2CR7U62h6sMyOeWI12sgWCK9EBP8z8T9WZoW44WCZvWuDUxjLgO90-wWDHbviqAm7ULS7h2CQmXao",
  "scope": "openid",
  "id_token": "eyJraWQiOiI4MzViZTNkOC1mZWFhLTRmZTQtOTI3YS1lMjRmNjliOGFjYTUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoiZnJvbnQtZW5kLWFwcCIsImF6cCI6ImZyb250LWVuZC1hcHAiLCJhdXRoX3RpbWUiOjE2OTYwMDE4NTIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMCIsImV4cCI6MTY5NjAwNTkzMSwiaWF0IjoxNjk2MDA0MTMxLCJub25jZSI6ImRkM2VtbWY3ZHBxIiwic2lkIjoiczVLLXFEYVpXNUM5NFY4RksyYTcweHpKaC1VNHVWODJrdXFhV1Y1VVUtZyJ9.GJSi6KOMJCFSMsPvf6I_9KrnxnKbNlb6aIpCaJHpDCujzkcP1XTbqIWZ5R6cBF5Fc3GNLNZ1N8PVJOwVI5q2C-xhFnmFjKoClHcwfDu9pRQKJPgPWBwsoKjiSr6ekhFdD5sIzap67iR-_l4tXZ7HmdUJ0wLaMMcLVMVlsiq-ekxUzwkNzc6fOe4BVX56-yWn0BTRogSW-C7o6wDkPcF7c7OprvSyygk2Oi7CS5ayd-mSWdD9DVOuRegDl2WXfURz9P3SDYwX_aWRtuxsL1DkehK_EzHXZeLfI0i48-1MsmmjSaQivO_9dkHKW_z9uBITbJhOVlHsKAGHVncKnqZrCA",
  "token_type": "Bearer",
  "expires_in": 300
}
````

Como observamos, utilizamos `curl` para enviar el request y poder obtener el `access_token`. También podríamos haber
usado `Postman` y definido los parámetros en el `Body: x-www-form-urlencoded` y en el `Authorization` haber
seleccionado el `Basic Auth`. De todas maneras a continuación se explican los parámetros usados:

- `[POST] http://localhost:9000/oauth2/token`, para solicitar al servidor de autorización el access token.
- `-u front-end-app:secret-key`, con esto definimos mediante curl el `Authorization: Basic Auth` colocando el username y
  password correspondiente al `cliente` registrado en el servidor de autorización de OAuth2.
- `grant_type`, el tipo de concesión es `authorization_code`.
- `client_id`, el identificador del cliente registrado en el servidor de autorización.
- `redirect_uri`, la uri de redirección registrado para el cliente en el servidor de autorización.
- `code_verifier`, código que usamos porque activamos el uso de `PKCE`.
- `code`, corresponde al `authorization code` obtenido en la página `oauthdebugger` luego de iniciar sesión
  exitosamente.

**IMPORTANTE**
> **Tenga en cuenta que un código de autorización solo se puede usar una vez.** Si intenta llamar al endpoint
> `/oauth2/token` usando el mismo código nuevamente, recibirá un error como el que se muestra en la parte inferior.
> Solo puede obtener otro código de autorización válido pidiéndole al usuario que inicie sesión nuevamente.

````json
{
  "error": "invalid_grant"
}
````

Finalmente, si decodificamos nuestro `access_token` veremos los datos que tenemos:

![7-decoded-access_token](./assets/7-decoded-access_token.png)

---

# CAPÍTULO 2: Registrando usuarios

---

## Dependencias y configuración del DataSource

En este capítulo trabajaremos con la entidad `User` y su registro en bases de datos, para eso, necesitamos agregar las
siguientes dos dependencias en nuestro `pom.xml`:

````xml

<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>

    <dependency>
        <groupId>com.mysql</groupId>
        <artifactId>mysql-connector-j</artifactId>
        <scope>runtime</scope>
    </dependency>
</dependencies>
````

Además, necesitamos configurar la conexión a la base de datos en el `application.yml`:

````yaml
# Otras configuraciones
# 
# Conexión a MySQL
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/db_spring_boot_oauth2
    username: root
    password: magadiflo

  # Configuraciones de Hibernate/Jpa
  jpa:
    properties:
      hibernate:
        dialect: org.hibernate.dialect.MySQLDialect
        format_sql: true
    show-sql: true
    defer-datasource-initialization: true
    generate-ddl: false
    hibernate:
      ddl-auto: update
````

**DONDE**

- `spring.jpa.defer-datasource-initialization = true`, se utiliza para controlar si Spring debe retrasar la
  inicialización del DataSource hasta después de que se haya configurado la capa de persistencia JPA. Por defecto, los
  scripts `data.sql` se ejecutan antes de que se inicialice Hibernate. Necesitamos que Hibernate cree nuestras tablas
  antes de insertar los datos en ellas. Para conseguirlo, necesitamos retrasar la inicialización de nuestro DataSource.
  Aunque vale la pena precisar, por el momento no estamos usando ningún script, pero lo dejaré configurado tal como lo
  está trabajando el tutor.

## Entidad User y Role

Crearemos un enum llamado `RoleName` donde definiremos los dos roles que estarán disponibles en nuestra aplicación:

````java
public enum RoleName {
    ROLE_ADMIN, ROLE_USER
}
````

Creamos la entidad `Role`:

````java

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
@Entity
@Table(name = "roles")
public class Role implements GrantedAuthority {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Enumerated(EnumType.STRING)
    private RoleName role;

    @Override
    public String getAuthority() {
        return this.role.name();
    }
}
````

Creamos la entidad `User` y establecemos la relación de `@ManyToMany` con la entidad `Role`:

````java

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
@Entity
@Table(name = "users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "users_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    private boolean expired = false;
    private boolean locked = false;
    private boolean credentialsExpired = false;
    private boolean disabled = false;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles;
    }

    @Override
    public boolean isAccountNonExpired() {
        return !this.expired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !this.locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !this.credentialsExpired;
    }

    @Override
    public boolean isEnabled() {
        return !this.disabled;
    }
}
````

## Capas: controller, service y repository para la entidad User y Role

Crearemos la **capa repository** para la entidad `User` y `Role` donde definiremos en cada uno un método personalizado:

````java
// IUserRepository
public interface IUserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}

// IRoleRepository
public interface IRoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRole(RoleName roleName);
}
````

Antes de continuar con la **capa de servicio** necesitamos crear los **DTOs** que usaremos para enviar/recibir
información al/desde cliente:

````java
// Record: MessageDTO
public record MessageDTO(String message) {
}

// Record: CreateUserDTO
public record CreateUserDTO(String username, String password, List<String> roles) {
}
````

Ahora sí, es momento de crear la **capa de servicio**:

````java
public interface IUserService {
    MessageDTO createUser(CreateUserDTO dto);
}
````

````java

@Slf4j
@RequiredArgsConstructor
@Service
public class UserServiceImpl implements IUserService {

    private final IUserRepository userRepository;
    private final IRoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public MessageDTO createUser(CreateUserDTO dto) {
        Set<Role> roles = dto.roles().stream()
                .map(RoleName::valueOf)
                .map(roleName -> this.roleRepository.findByRole(roleName)
                        .orElseThrow(() -> new RuntimeException("Role no encontrado")))
                .collect(Collectors.toSet());

        User user = User.builder()
                .username(dto.username())
                .password(this.passwordEncoder.encode(dto.password()))
                .roles(roles)
                .build();

        this.userRepository.save(user);

        return new MessageDTO(String.format("Usuario %s guardado", user.getUsername()));
    }
}
````

También necesitamos crear una implementación de la interfaz `UserDetailsService`, pues como ahora vamos a utilizar una
base de datos, necesitamos tener una implementación de esta interfaz para que busque al usuario por su username.
Debemos recordar que en el capítulo anterior usamos la clase concreta `InMemoryUserDetailsManager(...)` como
implementación del `UserDetailsService` que nos proporciona Spring para definir nuestro usuario, pero ahora, nosotros
crearemos nuestra propia implementación del `UserDetailsService` y la anterior configuración será eliminada.

Finalmente, toca crear nuestra **capa de controlador**:

````java

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
````

## Configuraciones de seguridad

Redefinimos el contenido de la clase `UserManagementConfig`, donde eliminaremos el `@Bean UserDetailsService` quien nos
estaba retornando la implementación `InMemoryUserDetailsManager` con nuestro usuario, pues ya no lo necesitamos debido a
que hemos creado una propia implementación. Además, requerimos ahora definir nuestro `@Bean` del `PasswordEncoder` para
poder cifrar la contraseña del usuario y del cliente:

````java

@Configuration
public class UserManagementConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
````

Finalmente, en nuestra clase principal de configuración de seguridad `SecurityConfig` realizaremos algunas
modificaciones:

````java

@Slf4j
@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final PasswordEncoder passwordEncoder;

    /* other code */

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());
        http.csrf(csrfConfigurer -> csrfConfigurer.ignoringRequestMatchers("/api/v1/auth/**"));
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("front-end-app")
                .clientSecret(this.passwordEncoder.encode("secret-key"))
                /* more configurations */
                .build();

        return new InMemoryRegisteredClientRepository(oidcClient);
    }
}
````

Como se observa en el código anterior, primero inyectamos el `PasswordEncoder` que usaremos para cifrar la contraseña
del cliente. Luego, en el `@Bean` de order 2 permitimos que se puedan realizar solicitudes a nuestro endpoint
`/api/v1/auth` si necesidad de autenticarse y además ignoramos el `CSRF` para ese mismo endpoint.

Un cambio más que se hizo en la clase anterior fue el cifrado que se realizó al `clientSecret` del cliente registrado
en memoria.

## Registrando Roles en la base de datos

Podemos crear manualmente en la base de datos los roles para nuestros usuarios en la aplicación, pero en esta
oportunidad usaremos la interfaz funcional `CommandLineRunner` para poder definir un `@Bean` y desde allí poder
registrar los roles usando el repositorio del rol:

````java

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
            this.roleRepository.saveAll(List.of(adminRole, userRole));
        };
    }
}
````

**NOTA**
> **Este código debe ser ejecutado una vez**, luego de que verifiquemos que en nuestra base de datos ya están
> registrados los dos roles, procederemos a comentar el código de inserción para que no lo vuelva a insertar cada vez
> que iniciemos la aplicación, aunque también podríamos eliminarlo, pero en mi caso solo lo comentaré.

## Ejecutando aplicación

Luego de ejecutar la aplicación por primera vez, en consola se mostrará el comando utilizado para la creación de
las tablas y posteriormente la inserción de los registros de roles. Luego, si revisamos la base de datos observaremos
que nuestras tablas fueron creados correctamente:

![8-users-roles-db](./assets/8-users-roles-db.png)

El siguiente paso es crear un par de usuarios, uno será `user` y el otro `admin`:

````bash
curl -v -X POST -H "Content-Type: application/json" -d "{\"username\": \"admin\", \"password\": \"12345\", \"roles\": [\"ROLE_ADMIN\", \"ROLE_USER\"]}" http://localhost:9000/api/v1/auth | jq

>
< HTTP/1.1 201
<
{
  "message": "Usuario admin guardado"
}
````

````bash
curl -v -X POST -H "Content-Type: application/json" -d "{\"username\": \"user\", \"password\": \"12345\", \"roles\": [\"ROLE_USER\"]}" http://localhost:9000/api/v1/auth | jq

>
< HTTP/1.1 201
<
{
  "message": "Usuario user guardado"
}
````

Ahora, utilizaremos la página de [oauthdebugger](https://oauthdebugger.com/debug) para solicitar un código de
autorización. Las configuraciones serán similares a la configuración que vimos en el primer capítulo:

![9-oauthdebugger](./assets/9-oauthdebugger.png)

Luego de hacer clic en `send request` la página de **oauthdebugger** nos redireccionará al login donde podremos usar
nuestros usuarios recién registrados:

![10-login](./assets/10-login.png)

Al loguearnos, seremos redirigidos a la página de **authdebugger** donde tendremos el **código de autorización**
solicitado:

![11-debugger-success.png](./assets/11-debugger-success.png)

Ahora utilizaremos el **código de autorización** para solicitar un **access token** al **servidor de autorización**,
obviamente requerimos los otros datos adicionales como el **client_id**, credenciales del cliente enviados vía
Authentication Basic Auth, etc. pero el punto aquí, es que nos estamos enfocando en cómo es que usamos el
`authorization code` para solicitar el `access token` al servidor de autorización:

````bash
curl -v -X POST -u front-end-app:secret-key -d "grant_type=authorization_code&client_id=front-end-app&redirect_uri=https://oauthdebugger.com/debug&code_verifier=yvlVXnbW7RKFj9Aq3GCB8QlFq1mnGJxYaIusXUxk477&code=JFP0_xKNJZoIawPhTPcowiPGp-qT9enMehaoUBWMGd4hrx1jkEYQxd5pA63kF3lPiEgA5NCBD6ujjCQy5ThCwlS8YTRq2uhTdPLv6dMsKWPg1nhORjx-eU7TNoIMLA-I" http://localhost:9000/oauth2/token | jq

> POST /oauth2/token HTTP/1.1
> Host: localhost:9000
> Authorization: Basic ZnJvbnQtZW5kLWFwcDpzZWNyZXQta2V5
> Content-Type: application/x-www-form-urlencoded
>
< HTTP/1.1 200
<
{
  "access_token": "eyJraWQiOiI3YWU5ZDk4NC02MzY4LTQxNzItOWY0NC1kZjkxYTM2MDhjZGMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6ImZyb250LWVuZC1hcHAiLCJuYmYiOjE2OTYwNTIwMjQsInNjb3BlIjpbIm9wZW5pZCJdLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJleHAiOjE2OTYwNTIzMjQsImlhdCI6MTY5NjA1MjAyNH0.dtbVzhv4l2X-4grxn5DXUiOJkmgU_LkB5cehPBF05s25Fs64IaYhq4DYkC54-LiimYnc2YqjDnaw9DYfWBBRNyoy_WQQeSITaBmBRCGLFHBq-1IrttelBrgAVf_RGYiAOhbV7Yr6Nsx78iO72zzzOP_4WXHG_sO3npSlbK9KNGejEoO8XgdKzxEeLzQCqgMt4zZrK_cr9Q2TZ1CALKsss7n76EbekStwxXC8ajAP4l82TxOotJIxaPvch6Rj2cuF8C1YYJmPCT5nfBN3S5cURswpBBIkgQwVej62B-KlWn3-k7AZCSFXQGyDJHC1sQNE2BdR9vSPFNPl8LigKFIr-Q",
  "refresh_token": "Lc2WgjSgoxmURd-xXp_uSmKfjfLb2ij-Urn8kABIsBZOCXtLCzFQDOXRIDCZqFXv2OK1bkcUDyYp8PakFk9gQy_rq0JkpQ3PXZE4WpYmYwKGU3v4AMe4ilP5gTjnfTKy",
  "scope": "openid",
  "id_token": "eyJraWQiOiI3YWU5ZDk4NC02MzY4LTQxNzItOWY0NC1kZjkxYTM2MDhjZGMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6ImZyb250LWVuZC1hcHAiLCJhenAiOiJmcm9udC1lbmQtYXBwIiwiYXV0aF90aW1lIjoxNjk2MDUxNzM5LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJleHAiOjE2OTYwNTM4MjQsImlhdCI6MTY5NjA1MjAyNCwibm9uY2UiOiJtc2c5Z24wdGl4NyIsInNpZCI6Im9rR21WSmF1TW8xRHQzVHc3UkVHeVMzSUliYV9oRUx6LVRzV2RhZkRYNkUifQ.BUQeiZ-Y0t9iKo4LO7tn2PMriTCCVzo95zlaH8FV1Ez_6B_YHvrQWCKJ9LWQRk2W1PwVY9G3SAy4AzjKhARPedJZGU3f07ZpV-3Y6bXNf6r61dpkT82zcdAAPRr4bPgMKp-enWaQsO0PjJuhDkZLvIC4YR-B7evWIizhk7FdxTTqEkjEH1lh2Hq3sQuwsPhbtrmJZz4HmtVnBeG9-UDKIYdvmdDVooNga2HCToYwTpFW9bzMcCAaeZlwWktZNGHsikeH0DdHPlUMlC-CbmH4qJbD5gun-VeLL3ZoYf2pKjYweR-kDZKG4Eb5YFlXtVz5rkv0bF7TzYginuOZFBQNTg",
  "token_type": "Bearer",
  "expires_in": 299
}
````
