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

