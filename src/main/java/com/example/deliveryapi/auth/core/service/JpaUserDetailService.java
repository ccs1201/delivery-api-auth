package com.example.deliveryapi.auth.core.service;

import com.example.deliveryapi.auth.core.domain.entity.AuthUser;
import com.example.deliveryapi.auth.core.domain.repository.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JpaUserDetailService implements UserDetailsService {

    private final UsuarioRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        var usuario = repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuário ou senha inválido."));

        return new AuthUser(usuario);
    }
}
