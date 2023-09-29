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

