package com.example.deliveryapi.auth.configurations;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;

@Validated
@Component
@ConfigurationProperties("delivery.jwt.config")
@Getter
@Setter
public class JwtKeyProperties {

    @NotBlank
    private String path;
    @NotBlank
    private String password;
    @NotBlank
    private String keyPairAlias;

}
