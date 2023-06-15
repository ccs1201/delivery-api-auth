package com.example.deliveryapi.auth.domain;

import lombok.Getter;
import org.springframework.security.core.userdetails.User;

import java.util.List;

@Getter
public class AuthUser extends User {

    private String nomeCompleto;
    private Long userId;

    public AuthUser(Usuario usuario) {
        super(usuario.getEmail(), usuario.getSenha(), List.of());
        nomeCompleto = usuario.getNome();
        userId = usuario.getId();
    }

}
