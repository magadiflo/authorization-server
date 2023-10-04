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

Si decodificamos el **access_token** obtenido veremos la información que contiene:

![12-decoded_access_token_user_db](./assets/12-decoded_access_token_user_db.png)

## Añadiendo Claims al JWT

La información decodificada del `access_token` anterior `no muestra el rol` que le asignamos al usuario `admin`, pese a
que sí tiene roles y están registrados en la base de datos. Entonces, lo que debemos hacer es modificar el jwt
agregándole los claims faltantes.

En la clase `SecurityConfig` agregamos un nuevo `@Bean` que nos permitirá agregar el rol o roles del usuario al jwt:

````java

@Slf4j
@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {
    /* other code */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            Authentication principal = context.getPrincipal();
            if (context.getTokenType().getValue().equals("id_token")) {
                context.getClaims()
                        .claim("token_type", "id token")
                        .build();
            }
            if (context.getTokenType().getValue().equals("access_token")) {
                Set<String> roles = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());

                context.getClaims()
                        .claim("token_type", "access token")
                        .claim("username", principal.getName())
                        .claim("roles", roles)
                        .build();
            }
        };
    }
    /* other code */
}
````

**DONDE**

- `OAuth2TokenCustomizer`, las implementaciones de esta interfaz son responsables de personalizar los atributos del
  token OAuth 2.0 contenidos en OAuth2TokenContext.
- `context`, el contexto que contiene los atributos del token OAuth 2.0.

### Verificando información añadida en el access_token

Iniciamos la aplicación e ingresamos a la página de [oauthdebugger.com/debug](https://oauthdebugger.com/debug),
completamos los datos solicitados como lo hemos venido trabajando desde el inicio y copiamos el **code verifier**,
damos en `send request`, iniciamos sesión con nuestra cuenta `admin` y pass `12345` para que el servidor de autorización
nos retorne un `authorization code`.

Con el código de autorización y el code verifier en nuestras manos, procedemos a solicitar el token:

````bash
curl -v -X POST -u front-end-app:secret-key -d "grant_type=authorization_code&client_id=front-end-app&redirect_uri=https://oauthdebugger.com/debug&code_verifier=CPsSpKNiVfsbw7RuDvP8jeZ9BeyFjtwOMd6lDfCvscu&code=ZuEPt_Q1mWd8kgMt9z7mURJeYJpRSWv1lmuwhp_sh6fW4Uq3cN8ECIKHhjApxulDIKk40cqkMwsYtHSffPkCY5tWKMcc9qK3KhAGtoqAWpDqlgfffrO3_lIHm9pxroqn" http://localhost:9000/oauth2/token | jq

> POST /oauth2/token HTTP/1.1
> Host: localhost:9000
> Authorization: Basic ZnJvbnQtZW5kLWFwcDpzZWNyZXQta2V5
> Content-Type: application/x-www-form-urlencoded
>
< HTTP/1.1 200
<
{
  "access_token": "eyJraWQiOiJmZmE2M2RlZi1mMDAwLTRkYjUtOGRkOS1hZTYwZWIzZmJiNTEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6ImZyb250LWVuZC1hcHAiLCJuYmYiOjE2OTYyMDE4NDgsInNjb3BlIjpbIm9wZW5pZCJdLCJyb2xlcyI6WyJST0xFX1VTRVIiLCJST0xFX0FETUlOIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMCIsImV4cCI6MTY5NjIwMjE0OCwidG9rZW5fdHlwZSI6ImFjY2VzcyB0b2tlbiIsImlhdCI6MTY5NjIwMTg0OCwidXNlcm5hbWUiOiJhZG1pbiJ9.IubqkYkDBVqHJqnn47TluGreuw3vyORrJ6zbB6iPR1m0-ieu3IHIAyQLdjSJsj5eAMBn8Y1JuuMun8DQB9Aek72dVn64ofFCLBffjn84yh5kfe3kRrk4x30bBBBvi1BGrDOBMjzKBCqdSmQra7bO8VwBFDXWXlJijXbkEaYycCt9NywCS7IGuA3-B4rMmfxzdZ7mz_WbipE14qAqmEjrNd2r64shyOb0vrLFZxmX7sJ8Zr_PJpzYXIUAdwsJfb0zdi9m-RHFF0rDPZcpGVDK8DYo2j5L4MS8va4c97qrxBXb0ncntadfU_q4fpW_fU95YtWcHLcRhbOSQkF5bTF7-Q",
  "refresh_token": "KjmkllHaiQRpTPjHqLQl1ydDORGoFAf4Z2L-56MU0AAjtFYBz5VkFdTEqWmg_O5YGRIJDFfdzQ8_1td1XuvRqmzyo9TvNpZgnaM2A3HQnxNg1WTJZxQHKKdrS8ovun-T",
  "scope": "openid",
  "id_token": "eyJraWQiOiJmZmE2M2RlZi1mMDAwLTRkYjUtOGRkOS1hZTYwZWIzZmJiNTEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6ImZyb250LWVuZC1hcHAiLCJhenAiOiJmcm9udC1lbmQtYXBwIiwiYXV0aF90aW1lIjoxNjk2MjAxNTIwLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJleHAiOjE2OTYyMDM2NDgsInRva2VuX3R5cGUiOiJpZCB0b2tlbiIsImlhdCI6MTY5NjIwMTg0OCwibm9uY2UiOiJ2d2VyOWZvaDF0ZCIsInNpZCI6ImJJZnNwcENqaU8tUlIyWHdnWmNibXY2VjFaWVB2bXZyTmpJS1pQQ1c0X00ifQ.wiXUmtBFdwPReIos9zSHzkj-036fmeUQFcY5l3rndyXvXim2nNyRAemPLDEkt3TGhtk65DYZYN9L-Hjr1PjQyp6y-_ayZh1JmhHhQ8mdXLlXM5xPZEho0Rt4FgAw-B-z4c--iVXWiAt3PmiufNpItFZAJGavAmvL19DWDBbCGU6zQ_Y8zO8xApcHpIeYBcWAhNo_3qraCGXFFvedqm-Q_670E_u3EkqjZU-CrU0IjHBht-9ZELV0myYFpS9mFwqq4PKpn0-Ri8D129Pm9hu6KDX_p9klrYkH2idXBCdT4DPduNqqf_vHdxJfqTg618QDvab4yoYoxsay6fpor5Ki2Q",
  "token_type": "Bearer",
  "expires_in": 300
}

````

Ahora, si decodificamos el **access_token** veremos que ya tenemos la información que le agregamos en la configuración:

![13-decoded-access_token-roles](./assets/13-decoded-access_token-roles.png)

---

# CAPÍTULO 3: Registrando clientes (frontEnd)

---

En el capítulo anterior trabajamos con la entidad `User` que nos permitió registrar usuarios en la base de datos. En
este capítulo trabajaremos con la entidad `Client` que hace referencia al `Cliente` dentro de la arquitectura de
`OAuth2`, es decir información sobre nuestra aplicación cliente que será registrado en el servidor de Autorización.

## Entidad Client

Recordemos que en los capítulos anteriores se creó un cliente llamado `front-end-app` a quien registré en memoria
dentro del servidor de autorización. Este cliente fue un objeto del tipo `RegisteredClient` **(representación de un
cliente que está registrado en el servidor de autorización)** a quien le definimos varios
atributos, tales como: **withId(), clientId(), clientSecret(), clientAuthenticationMethod(), etc.** Ahora, necesitamos
tener esa representación del cliente pero para poder registrarlo en la base de datos, por lo tanto, crearemos nuestra
entidad `Client` que tendrá los mismos atributos mencionados anteriormente:

````java

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
@Entity
@Table(name = "clients")
public class Client {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String clientId;
    private String clientSecret;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<ClientAuthenticationMethod> clientAuthenticationMethods;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> redirectUris;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> scopes;
    private boolean requireProofKey;

    public static RegisteredClient toRegisteredClient(Client client) {
        return RegisteredClient.withId(client.getClientId())
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .clientIdIssuedAt(Instant.now())
                .clientAuthenticationMethods(clientAM -> clientAM.addAll(client.getClientAuthenticationMethods()))
                .authorizationGrantTypes(authorizationGT -> authorizationGT.addAll(client.getAuthorizationGrantTypes()))
                .redirectUris(redirectUris -> redirectUris.addAll(client.getRedirectUris()))
                .scopes(scopes -> scopes.addAll(client.getScopes()))
                .clientSettings(ClientSettings.builder().requireProofKey(client.isRequireProofKey()).build())
                .build();
    }
}
````

La anotación `@ElementCollection(fetch = FetchType.EAGER)` fue colocada en todas las propiedades de colección con la
finalidad que al ejecutar la aplicación Hibernate/JPA creará una nueva tabla de la propiedad sobre la que está anotada
conteniendo además la referencia a esta tabla cliente. Es decir, en la base de datos se creará la entidad `Client`
conteniendo únicamente 4 columnas: **id, clientId, clientSecret y requireProofKey**; mientras que, para las demás
propiedades de colección se creará su respectiva tabla con una referencia a la entidad `Client`. Esto es para no entrar
tanto en detalles, porque fácilmente habríamos creado una entidad por cada colección y haber establecido la relación con
la entidad Client mediante código, pero para hacerlo rápido es que usamos la anotación
`ElementCollection(fetch = FetchType.EAGER)`. Ah, si por ejemplo, no usáramos la anotación en la propiedad de colección,
lo que pasará es que se creará en la entidad `Client` la propiedad de colección y será del tipo `Varbinary`.

Adicionalmente, observamos que creamos un método estático `toRegisteredClient()` para que a partir de una
entidad `Client` podamos convertirlo a una representación de un cliente que está registrado en el servidor de
autorización: `RegisteredClient`.

**IMPORTANTE**
> Se tomó como referencia además la documentación
> [spring-authorization-server/client-entity](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/guides/how-to-jpa.html#client-entity)

## Client Repository y DTO

Creamos el repositorio `IClientRepository` para la entidad `Client` donde definiremos un método personalizado para poder
recuperar el Client a través de su atributo `clientId`:

````java
public interface IClientRepository extends JpaRepository<Client, Long> {
    Optional<Client> findByClientId(String clientId);
}
````

Creamos nuestro `CreateClientDTO`:

````java
public record CreateClientDTO(String clientId, String clientSecret,
                              Set<ClientAuthenticationMethod> clientAuthenticationMethods,
                              Set<AuthorizationGrantType> authorizationGrantTypes, Set<String> redirectUris,
                              Set<String> scopes, boolean requireProofKey) {
}
````

## Client Service

Si vemos los capítulos iniciales, recordaremos que creamos un `@Bean` en el `SecurityConfig` del tipo
`RegisteredClientRepository` **(un repositorio para clientes registrados de OAuth 2.0.)** que era el tipo del método
con el que retornábamos al cliente registrado. Ahora, como ese `@Bean` será eliminado, pues hasta este punto ya estamos
trabajando con base de datos, necesitamos de todas maneras tener ese objeto para poder manipular a los clientes
registrados en OAuth2.

Entonces, crearemos una interfaz llamada `IClientService` que extenderá de la interfaz `RegisteredClientRepository` que
es propio del servidor de autorización OAuth2. **¿Por qué hago eso?**, porque si observamos los métodos que tiene la
segunda interfaz veremos que son:

````java
public interface RegisteredClientRepository {
    void save(RegisteredClient registeredClient);

    @Nullable
    RegisteredClient findById(String id);

    @Nullable
    RegisteredClient findByClientId(String clientId);
}
````

El método `save()` retorna un `void` y lo que en nuestro caso queremos hacer es retornar un objeto del
tipo `MessageDTO`, por lo tanto, necesitamos definir un método personalizado en nuestra interfaz del servicio para
poder crear el registro del Cliente y luego retornar el objeto del tipo `MessageDTO`. Al hacer esto, cuando
implementemos la interfaz `IClientService` en la clase concreta `ClientServiceImpl` sobreescribiremos todos los métodos
que existan en ambas interfaces:

````java
public interface IClientService extends RegisteredClientRepository {
    MessageDTO create(CreateClientDTO dto);
}
````

Creamos la interfaz `ClientServiceImpl` e implementamos su interfaz `IClientService` que a su vez está extendiendo
de `RegisteredClientRepository`:

````java

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
````

## Client Controller

Creamos el controlador que nos permitirá definir un endpoint para poder crear a los clientes:

````java

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
````

## Modificando la clase SecurityConfig

Habilitamos el endpoint `/api/v1/clients`:

````java

@Slf4j
@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {
    /* other code */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/v1/auth/**", "/api/v1/clients/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());
        http.csrf(csrfConfigurer -> csrfConfigurer.ignoringRequestMatchers("/api/v1/auth/**", "/api/v1/clients/**"));
        return http.build();
    }
    /* other code */
}
````

Notar que en esta clase eliminamos el `@Bean RegisteredClientRepository y el ClientSettings`, ya que ya no lo
necesitamos, pues ahora registraremos a nuestros clientes en base de datos.

## Ejecutando aplicación y registrando un cliente

Al ejecutar la aplicación por primera vez vemos que se nos crean nuevas tablas en la base de datos:

![Clients db](./assets/14-clients-db.png)

Hasta este punto no tenemos ningún cliente registrado, por lo que si nos intentamos loguear nos lanzará un error:

![15-login-sin-cliente-en-bd](./assets/15-login-sin-cliente-en-bd.png)

![16-error-login-sin-cliente-bd](./assets/16-error-login-sin-cliente-bd.png)

**NOTA**
> Recordar que este proceso de login es utilizando la página de [oauthdebugger/debug](https://oauthdebugger.com/debug`)

Ahora, procedemos a registrar nuestro cliente `front-end-app`:

````bash
curl -v -X POST -H "Content-Type: application/json" -d "{\"clientId\": \"front-end-app\", \"clientSecret\": \"secret-key\", \"clientAuthenticationMethods\": [\"client_secret_basic\"], \"authorizationGrantTypes\": [\"authorization_code\", \"refresh_token\", \"client_credentials\"], \"redirectUris\": [\"https://oauthdebugger.com/debug\"], \"scopes\": [\"openid\", \"profile\"], \"requireProofKey\": true}" http://localhost:9000/api/v1/clients | jq

>
< HTTP/1.1 201
<
{
  "message": "Cliente front-end-app registrado"
}
````

Listo, ahora sí tenemos registrado a un cliente en la base de datos, por lo que en esta ocasión el proceso de logueo,
que es para solicitar un `Authorization Code` sí funcionará:

![17-login-success-authorization-code](./assets/17-login-success-authorization-code.png)

Ahora utilizaremos dicho código para solicitar el `Access Token`:

````bash
curl -v -X POST -u front-end-app:secret-key -d "grant_type=authorization_code&client_id=front-end-app&redirect_uri=https://oauthdebugger.com/debug&code_verifier=BxD0xaf1Qal7ETQ8zGfFbWQu6rljnsMVQX2EJ8Fjswm&code=bX_9YzpJgXoeXpj7_bO_poOVaryjtdEcGOQl5dYrDGRSZ8YjEA3NhKFaPhhv7-xfkLYZXqJD-TK-PKxciV5X9nM9yiQaflM2IFMzdYSpNCnUSPxA_ZUEAGp5GCBTN3zH" http://localhost:9000/oauth2/token | jq

> POST /oauth2/token HTTP/1.1
> Host: localhost:9000
> Authorization: Basic ZnJvbnQtZW5kLWFwcDpzZWNyZXQta2V5
> Content-Type: application/x-www-form-urlencoded
>
} [290 bytes data]
< HTTP/1.1 200
<
{
  "access_token": "eyJraWQiOiJkZGU3YzIxOS0zNTE4LTRhNGMtOTc1ZC0zOGYzYjE5M2IzN2IiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6ImZyb250LWVuZC1hcHAiLCJuYmYiOjE2OTYyMjQ5NzEsInNjb3BlIjpbIm9wZW5pZCJdLCJyb2xlcyI6WyJST0xFX1VTRVIiLCJST0xFX0FETUlOIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMCIsImV4cCI6MTY5NjIyNTI3MSwidG9rZW5fdHlwZSI6ImFjY2VzcyB0b2tlbiIsImlhdCI6MTY5NjIyNDk3MSwidXNlcm5hbWUiOiJhZG1pbiJ9.ngmILqUIEoTYA9SrxMH6ambnwa3mFI7ZroRR42luJ-HBr4UtzkbXpZUoiCwGK_05FYUaXyHP56qPONkunpaA3TnUBorvCCkqMWcn5S1B62_LJ-6Yue2PW42h5NQQteb70XxEedeCQNk86ThhCNxAbHFLpyOMX6G3ICVDCol97MJYKQchmCco2uqXXxG9S_JdpPu-fHdatwxURunzrtGJinmaJdcOw8ErQzar4gkpLZHp8Aay7ndAhyYc6HpI6z2Fjpy41oZE06eg8pccz_kPCwIz7JcyAlY6m_mS_dWE6YPR6z1hXjRlW6QImB7KQwXug1rcIi76_UmmafT9b5zDjg",
  "refresh_token": "1UXYTLyGN6tQEVRgxLdW9c9I4Cv1ck1d5HLVBUEFnRyKmDNz8DoCeA9cw6jmXZ81IuijLQk1v2qZJ82oJcV07hKU1fChncQ67WX07_zi8xOO0wN6GlpmEvy0Bf4q8zg7",
  "scope": "openid",
  "id_token": "eyJraWQiOiJkZGU3YzIxOS0zNTE4LTRhNGMtOTc1ZC0zOGYzYjE5M2IzN2IiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6ImZyb250LWVuZC1hcHAiLCJhenAiOiJmcm9udC1lbmQtYXBwIiwiYXV0aF90aW1lIjoxNjk2MjI0Nzk3LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJleHAiOjE2OTYyMjY3NzEsInRva2VuX3R5cGUiOiJpZCB0b2tlbiIsImlhdCI6MTY5NjIyNDk3MSwibm9uY2UiOiJqYWF0bDBzcGFlcyIsInNpZCI6IlJrVTY4QlVZaHAxd1o1XzZfRVFiY19UUEktRTBzeWlQSjc2TzZseU45VmsifQ.j8e0KB_5Y265ZeCyaFUwHrFVyJeqAdbjcNW8OoqPU0PImi641WJC-E-fmFSRzfzpyN_shkUi77V5m3kWDLrBu_KfCnIDyjuZjQyDDdnr7LsUK1uN8EtwG68lbMim5itKCAZRDKufUU3zn6_fn3C40Ygp0Uy8VrnhSKFZecRnESE8qr5wwaVthsSgduUZkkMPRPJvrC-3skD7TVFwipZLpulKSFLtLSRp9Sbin4yhAh_1x-qSZv8jouy7aDX6Dc3tSQaVfRHvFPH6l3FqIxllWEMH167O6e5KxM_1ZEC35U1kAktVtg6uZt3t4XqUaO-BdrS5bLy9G-50n4xkHbPBHQ",
  "token_type": "Bearer",
  "expires_in": 299
}
````

Como observamos, todo está funcionando como antes, pero ahora nuestro `Cliente` **ya se encuentra registrado en
la base de datos** y no solo en memoria como lo teníamos en los capítulos iniciales.

Finalmente, hasta este punto, las tablas relacionadas con el `Authorization Server` quedarían de esta manera en la base
de datos:

![18.authorization-server-db](./assets/18.authorization-server-db.png)

---

# CAPÍTULO 5: Social Login - Google

- No coloco **CAPÍTULO 4** porque siguiendo el listado del tutorial el capítulo 4 trató sobre la implementación del
  [**Resource Server**](https://github.com/magadiflo/resource-server.git).
- **Referencia Oficial:**
  [Cómo: Autenticación mediante Social Login](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/guides/how-to-social-login.html)

---

## Registro con el proveedor de inicio de sesión social

Utilizaremos `Google` para que los usuarios puedan iniciar sesión. En ese sentido, el servidor de `Google` se convertirá
en nuestro `Authorization Server` para esta nueva funcionalidad de social login, mientras que nuestra aplicación de
`Spring Boot 3 authorization-server` se convertirá en un `cliente` del `Servidor de Autorización de Google`, por lo
tanto, necesitamos generar las credenciales para nuestra aplicación cliente (authorization-server), de esa manera
estaremos registrándolo en el servidor de Google.

> Con nuestra **cuenta de google iniciada**, accedemos a [console.cloud.google](https://console.cloud.google.com)

Como yo ya había trabajado anteriormente con **Google Cloud** es que aparece por defecto seleccionado el último proyecto
en el que trabajé. Entonces, **para poder crear un nuevo proyecto**, debemos hacer click en el `Select` y se nos abrirá
el
modal. Luego, en el paso **3** agrego un nombre al proyecto y damos en crear:

![19-cliente-google-1](./assets/19-cliente-google-1.png)

Ahora que tenemos creado el proyecto lo seleccionamos y vamos a la opción de **API APIs y servicios**:

![20-cliente-google-2](./assets/20-cliente-google-2.png)

Seguimos las siguientes opciones:

![21-cliente-google-3](./assets/21-cliente-google-3.png)

Seleccionamos la opción de **Externos** y damos en crear:

![22-cliente-google-4](./assets/22-cliente-google-4.png)

En la siguiente pantalla damos un nombre a la aplicación, colocamos nuestro correo de gmail 2 veces y damos en
**Guardar y Continuar**:

![23-cliente-google-5](./assets/23-cliente-google-5.png)

En la siguiente pantalla simplemente damos en **Guardar y Continuar** que nos llevará a la página para poder agregar
usuarios de prueba. Aquí es donde me agregaré a mí mismo como un usuario de prueba, luego damos **Guardar y Continuar**:

![24-cliente-google-6](./assets/24-cliente-google-6.png)

Luego de la pantalla anterior daremos click en el botón **VOLVER AL PANEL**. Ya en el panel, daremos clic en
Credenciales y **CREAR CREDENCIALES**:

![25-cliente-google-7](./assets/25-cliente-google-7.png)

**Esta parte es muy importante**, ya que aquí seleccionamos que el tipo de aplicación que vamos a registrar, en nuestro
caso será una **Aplicación Web** y además le tenemos que **dar un nombre a nuestra aplicación cliente**. Otro punto
importante es que en la parte inferior agregamos explícitamente las url de redireccionamiento que están autorizados
para nuestra aplicación cliente.

Según la **documentación oficial** que referencié al inicio de este capítulo, menciona que cuando lleguemos a este
punto del registro donde nos soliciten especificar un **URI de redirección**, debemos definir un `registrationId`
(como google, my-client o cualquier otro identificador único que desee) que utilizaremos para configurar tanto
Spring Security como su proveedor. En mi caso, elegí como un `registrationId` a `google-idp`. Si observamos la imagen
inferior, veremos que he encerrado en un círculo naranja ese identificador.

El `registrationId` **es un identificador único para el ClientRegistration en Spring Security**. La plantilla
Redirect URI predeterminada es `{baseUrl}/login/oauth2/code/{registrationId}`. Consulte
[Configuración del URI de redirección](https://docs.spring.io/spring-security/reference/servlet/oauth2/login/core.html#oauth2login-sample-redirect-uri)
en la referencia de Spring Security para obtener más información.

![26-cliente-google-8](./assets/26-cliente-google-8.png)

**NOTA**
> Las demás uris de redireccionamiento las coloqué siguiendo el video del tutorial, aunque según la documentación
> oficial, nos muestra como único uri de redireccionamiento el que configuramos con nuestro registrationId
> **google-idp**: `http://localhost:9000/login/oauth2/code/google-idp`

Finalmente, como último paso, Google nos mostrará las credenciales que deberá tener nuestra aplicación cliente:

![27-cliente-google-9](./assets/27-cliente-google-9.png)

## Usando .env en IntelliJ IDEA

Las credenciales que nos generó google no la debemos subir al repositorio por lo que optaremos por crear un archivo
`.env` en la raíz de nuestro proyecto donde definiremos las variables de entorno que contendrán nuestras credenciales:

````dotenv
GOOGLE_CLIENT_ID=580379...
GOOGLE_CLIENT_SECRET=GOCS...
````

Como estamos trabajando con **IntelliJ IDEA** necesitamos de alguna forma leer el archivo `.env` cada vez que ejecutemos
la aplicación, para eso debemos instalar el plugin [EnvFile](https://plugins.jetbrains.com/plugin/7861-envfile) y
a continuación agregar el archivo `.env` en la configuración de ejecución:

![28-env-intellij-idea](./assets/28-env-intellij-idea.png)

## Añadir dependencia de cliente OAuth2

En este capítulo, como estamos viendo el tema del **Social Login**, el **servidor de autorización** que creamos en los
capítulos iniciales con Spring Boot 3, las dependencias de OAuth2 Authorization Server, etc., ahora se convertirá
en un **Cliente** de **Google** y es **Google** quien ahora, será nuestro **Servidor de Autorización**; esa fue
la razón por la que en la sección anterior creamos los credenciales que usará esta aplicación cliente.

Entonces, como necesitamos que esta aplicación **authorization-server** sea un cliente OAuth2 de Google, agregaremos
la dependencia `spring-boot-starter-oauth2-client`; además, crearemos nuestro propio formulario html de login y logout,
por lo que necesitamos agregar la dependencia de `thymeleaf`:

````xml

<dependencies>
    <!--Other dependencies-->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-client</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
    </dependency>
    <!--Other dependencies-->
</dependencies>
````

## Registrar un cliente

A continuación, configure el `ClientRegistration` con los valores obtenidos anteriormente. Usando Google, configure las
siguientes propiedades:

````yml
spring:
  security:
    oauth2:
      client:
        registration:
          google-idp:
            provider: google
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope: openid, https://www.googleapis.com/auth/userinfo.profile, https://www.googleapis.com/auth/userinfo.email
            client-name: authorization-server-spring-boot-as-a-client
        provider:
          google:
            user-name-attribute: email
````

**DONDE**<br>
Fuente 1: [OpenId-Connect](https://developers.google.com/identity/openid-connect/openid-connect?hl=es-419#appsetup)<br>
Fuente 2: [OAuth2/scopes](https://developers.google.com/identity/protocols/oauth2/scopes?hl=es-419)

- El `registrationId` en el ejemplo anterior es `google-idp`, mismo que usamos en el uri de redireccionamiento de
  google.
- `provider`, es `google` como nuestro proveedor de inicio de sesión social.
- `client-id`, la string del ID de cliente que obtienes de `Credentials page` de API Console.
- `scope`, debe comenzar con el valor `openid` y, luego, incluir el valor `profile`, el valor `email` o ambos.
    - **openid**, asocie su cuenta con su información personal en Google.
    - **https://www.googleapis.com/auth/userinfo.profile**, permite ver su información personal, incluidos los datos
      personales que haya hecho públicos.
    - **https://www.googleapis.com/auth/userinfo.email**, consultar la dirección de correo electrónico principal de su
      Cuenta de Google.
- `client-name`, el nombre de tu cliente de OAuth 2.0. Este nombre solo se usa para identificar al cliente en la
  consola de `google cloud` y no se mostrará a los usuarios finales.
- `user-name-attribute`, el claim en `id_token` o en la respuesta de información del usuario que contiene el username
  del usuario.

## Configuraciones avanzadas para federar proveedores de identidades

La siguiente configuración `FederatedIdentityAuthenticationSuccessHandler` utiliza un componente personalizado para
**capturar usuarios** en una **base de datos local** cuando inician sesión por primera vez:

````java
public final class FederatedIdentityAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final AuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();

    private Consumer<OAuth2User> oauth2UserHandler = (user) -> {
    };

    private Consumer<OidcUser> oidcUserHandler = (user) -> this.oauth2UserHandler.accept(user);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        if (authentication instanceof OAuth2AuthenticationToken) {
            if (authentication.getPrincipal() instanceof OidcUser) {
                this.oidcUserHandler.accept((OidcUser) authentication.getPrincipal());
            } else if (authentication.getPrincipal() instanceof OAuth2User) {
                this.oauth2UserHandler.accept((OAuth2User) authentication.getPrincipal());
            }
        }
        this.delegate.onAuthenticationSuccess(request, response, authentication);
    }

    public void setOAuth2UserHandler(Consumer<OAuth2User> oauth2UserHandler) {
        this.oauth2UserHandler = oauth2UserHandler;
    }

    public void setOidcUserHandler(Consumer<OidcUser> oidcUserHandler) {
        this.oidcUserHandler = oidcUserHandler;
    }
}
````

Con el `FederatedIdentityAuthenticationSuccessHandler` anterior, puede conectar su propio `Consumer<OAuth2User>` que
puede capturar usuarios en una base de datos u otro almacén de datos para conceptos como vinculación de cuentas
federadas o aprovisionamiento de cuentas JIT. A continuación se muestra la clase que simplemente almacena usuarios en
la memoria:

````java
public final class UserRepositoryOAuth2UserHandler implements Consumer<OAuth2User> {

    private final UserRepository userRepository = new UserRepository();

    @Override
    public void accept(OAuth2User user) {
        // Capturar el usuario en un local data store en la primera autenticación
        if (this.userRepository.findByName(user.getName()) == null) {
            System.out.println("Guardando usuario por primera vez: name=" + user.getName() +
                               ", claims=" + user.getAttributes() + ", authorities=" + user.getAuthorities());
            this.userRepository.save(user);
        }
    }

    static class UserRepository {
        private final Map<String, OAuth2User> userCache = new ConcurrentHashMap<>();

        public OAuth2User findByName(String name) {
            return this.userCache.get(name);
        }

        public void save(OAuth2User oauth2User) {
            this.userCache.put(oauth2User.getName(), oauth2User);
        }
    }
}
````

A continuación se muestran dos clases que se crearon para personalizar la redirección al end-point de login de
OAuth 2.0 cuando no esté autenticado desde el end-point de autorización:

````java
public final class FederatedIdentityAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    // DEFAULT_AUTHORIZATION_REQUEST_BASE_URI= "/oauth2/authorization"
    private String authorizationRequestUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/{registrationId}";

    private final AuthenticationEntryPoint delegate;

    private final ClientRegistrationRepository clientRegistrationRepository;

    public FederatedIdentityAuthenticationEntryPoint(String loginPageUrl, ClientRegistrationRepository clientRegistrationRepository) {
        this.delegate = new LoginUrlAuthenticationEntryPoint(loginPageUrl);
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException)
            throws IOException, ServletException {
        String idp = request.getParameter("idp");//identity provider
        if (idp != null) {
            ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(idp);
            if (clientRegistration != null) {
                String redirectUri = UriComponentsBuilder.fromHttpRequest(new ServletServerHttpRequest(request))
                        .replaceQuery(null)
                        .replacePath(this.authorizationRequestUri)
                        .buildAndExpand(clientRegistration.getRegistrationId())
                        .toUriString();
                this.redirectStrategy.sendRedirect(request, response, redirectUri);
                return;
            }
        }

        this.delegate.commence(request, response, authenticationException);
    }

    public void setAuthorizationRequestUri(String authorizationRequestUri) {
        this.authorizationRequestUri = authorizationRequestUri;
    }
}
````

````java
public final class FederatedIdentityConfigure extends AbstractHttpConfigurer<FederatedIdentityConfigure, HttpSecurity> {

    private String loginPageUrl = "/login";

    private String authorizationRequestUri;

    private Consumer<OAuth2User> oauth2UserHandler;

    private Consumer<OidcUser> oidcUserHandler;

    /**
     * @param loginPageUrl The URL of the login page, defaults to {@code "/login"}
     * @return This configurer for additional configuration
     */
    public FederatedIdentityConfigure loginPageUrl(String loginPageUrl) {
        Assert.hasText(loginPageUrl, "loginPageUrl cannot be empty");
        this.loginPageUrl = loginPageUrl;
        return this;
    }

    /**
     * @param authorizationRequestUri The authorization request URI for initiating
     *                                the login flow with an external IDP, defaults to {@code
     *                                "/oauth2/authorization/{registrationId}"}
     * @return This configurer for additional configuration
     */
    public FederatedIdentityConfigure authorizationRequestUri(String authorizationRequestUri) {
        Assert.hasText(authorizationRequestUri, "authorizationRequestUri cannot be empty");
        this.authorizationRequestUri = authorizationRequestUri;
        return this;
    }

    /**
     * @param oauth2UserHandler The {@link 'Consumer'} for performing JIT account provisioning
     *                          with an OAuth 2.0 IDP
     * @return This configurer for additional configuration
     */
    public FederatedIdentityConfigure oauth2UserHandler(Consumer<OAuth2User> oauth2UserHandler) {
        Assert.notNull(oauth2UserHandler, "oauth2UserHandler cannot be null");
        this.oauth2UserHandler = oauth2UserHandler;
        return this;
    }

    /**
     * @param oidcUserHandler The {@link 'Consumer'} for performing JIT account provisioning
     *                        with an OpenID Connect 1.0 IDP
     * @return This configurer for additional configuration
     */
    public FederatedIdentityConfigure oidcUserHandler(Consumer<OidcUser> oidcUserHandler) {
        Assert.notNull(oidcUserHandler, "oidcUserHandler cannot be null");
        this.oidcUserHandler = oidcUserHandler;
        return this;
    }

    // @formatter:off
    @Override
    public void init(HttpSecurity http) throws Exception {
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        ClientRegistrationRepository clientRegistrationRepository =
                applicationContext.getBean(ClientRegistrationRepository.class);
        FederatedIdentityAuthenticationEntryPoint authenticationEntryPoint =
                new FederatedIdentityAuthenticationEntryPoint(this.loginPageUrl, clientRegistrationRepository);
        if (this.authorizationRequestUri != null) {
            authenticationEntryPoint.setAuthorizationRequestUri(this.authorizationRequestUri);
        }

        FederatedIdentityAuthenticationSuccessHandler authenticationSuccessHandler =
                new FederatedIdentityAuthenticationSuccessHandler();
        if (this.oauth2UserHandler != null) {
            authenticationSuccessHandler.setOAuth2UserHandler(this.oauth2UserHandler);
        }
        if (this.oidcUserHandler != null) {
            authenticationSuccessHandler.setOidcUserHandler(this.oidcUserHandler);
        }

        http.exceptionHandling(exceptionHandling ->
                        exceptionHandling.authenticationEntryPoint(authenticationEntryPoint)
                )
                .oauth2Login(oauth2Login -> {
                    oauth2Login.successHandler(authenticationSuccessHandler);
                    if (this.authorizationRequestUri != null) {
                        String baseUri = this.authorizationRequestUri.replace("/{registrationId}", "");
                        oauth2Login.authorizationEndpoint(authorizationEndpoint ->
                                authorizationEndpoint.baseUri(baseUri)
                        );
                    }
                });
    }
    // @formatter:on
}
````

**NOTA**
> Las clases `FederatedIdentityAuthenticationSuccessHandler` y `UserRepositoryOAuth2UserHandler` están tal cual en la
> documentación oficial
> [Capture Users in a Database](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/guides/how-to-social-login.html#advanced-use-cases-capture-users),
> mientras que las clases `FederatedIdentityAuthenticationEntryPoint` y `FederatedIdentityConfigure` fueron copiadas
> tal cual del tutorial, que a su vez lo copió del repositorio de Spring que está en GitHub.

