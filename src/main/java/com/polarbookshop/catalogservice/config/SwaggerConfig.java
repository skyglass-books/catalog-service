package com.polarbookshop.catalogservice.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springdoc.core.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Value("${spring.application.name}")
    private String applicationName;

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .components(
                        new Components()
                            .addSecuritySchemes(BEARER_KEY_SECURITY_SCHEME,
                                    new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT"))
                            .addSecuritySchemes("bearerAuth",
                                    new SecurityScheme()
                                            .type(SecurityScheme.Type.APIKEY)
                                            .name("Authorization")
                                            .in(SecurityScheme.In.HEADER)
                ))
                .info(new Info().title(applicationName))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));
    }

    @Bean
    public GroupedOpenApi customApi() {
        return GroupedOpenApi.builder()
                .group("books")
                /*.addOpenApiCustomiser(openApi -> {
                    openApi.getServers().clear();
                    openApi.addServersItem(new Server().url("https://books.greeta.net"));
                })*/
                .pathsToMatch("/books/**")
                .build();
    }

    @Bean
    public GroupedOpenApi actuatorApi() {
        return GroupedOpenApi.builder()
                .group("actuator")
                /*.addOpenApiCustomiser(openApi -> {
                    openApi.getServers().clear();
                    openApi.addServersItem(new Server().url("https://books.greeta.net"));
                })*/
                .pathsToMatch("/actuator/**").build();
    }

    public static final String BEARER_KEY_SECURITY_SCHEME = "bearer-key";

}
