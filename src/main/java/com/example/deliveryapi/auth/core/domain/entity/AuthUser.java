package com.example.deliveryapi.auth.core.domain.entity;

import lombok.Getter;
import org.springframework.security.core.userdetails.User;

import java.util.List;

@Getter
public class AuthUser extends User {

    private String nomeCompleto;

    public AuthUser(Usuario usuario) {
        super(usuario.getNome(), usuario.getSenha(), List.of());
        nomeCompleto = usuario.getNome();
    }

}
