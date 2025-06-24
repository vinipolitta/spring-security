package br.com.forum_hub.domain.usuario;

import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDate;
import java.util.List;

public record DadosListagemUsuario(Long id,
                                   String email,
                                   String nomeCompleto,
                                   String nomeUsuario,
                                   String miniBiografia,
                                   String biografia,
                                   List<String> perfis
) {
    public DadosListagemUsuario(Usuario usuario) {
        this(usuario.getId(), usuario.getUsername(),
                usuario.getNomeCompleto(), usuario.getNomeUsuario(),
                usuario.getMiniBiografia(), usuario.getBiografia(),
                usuario.getAuthorities().stream().map((GrantedAuthority::getAuthority)).toList());
    }
}