package br.com.forum_hub.infra.seguranca;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class ConfiguracoesSeguranca {

    private final FiltroTokenAcesso filtroTokenAcesso;

    public ConfiguracoesSeguranca(FiltroTokenAcesso filtroTokenAcesso) {
        this.filtroTokenAcesso = filtroTokenAcesso;
    }

    @Bean
    public SecurityFilterChain filtrosSeguranca(HttpSecurity http) throws Exception {
        return http
                // Configuração de autorizações por requisição
                .authorizeHttpRequests(req -> req
                        // Permitir acesso público às seguintes URLs
                        .requestMatchers(
                                "/login", "/atualizar-token", "/registrar", "/verificar-conta"
                        ).permitAll()
                        .requestMatchers(HttpMethod.GET, "/cursos").permitAll() // Permitir GET em /cursos
                        .requestMatchers(HttpMethod.GET, "/topicos/**").permitAll() // Permitir GET em /topicos/**

                        // Restringir acesso para operações específicas em /topicos
                        .requestMatchers(HttpMethod.POST, "/topicos").hasRole("ESTUDANTE")
                        .requestMatchers(HttpMethod.PUT, "/topicos").hasRole("ESTUDANTE")
                        .requestMatchers(HttpMethod.DELETE, "/topicos/**").hasRole("ESTUDANTE")
                        .requestMatchers(HttpMethod.PATCH, "/topicos/{idTopico}/respostas/**").hasAnyRole("INSTRUTOR", "MODERADOR", "ESTUDANTE")
                        .requestMatchers(HttpMethod.PATCH, "/topicos/**").hasRole("MODERADOR")

                        // Apenas usuários com papel ADMIN podem acessar /adicionar-perfil/**
                        .requestMatchers(HttpMethod.PATCH, "/adicionar-perfil/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PATCH, "/reativar-conta/**").hasRole("ADMIN")

                        // Qualquer outra requisição deve estar autenticada
                        .anyRequest().authenticated()
                )
                // Configuração de gerenciamento de sessão
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Desabilitar proteção CSRF
                .csrf(csrf -> csrf.disable())
                // Adicionar filtro de token de acesso antes do filtro padrão de autenticação
                .addFilterBefore(filtroTokenAcesso, UsernamePasswordAuthenticationFilter.class)
                .build();
    }


    @Bean
    public PasswordEncoder encriptador() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public RoleHierarchy hierarquiaPerfis() {
        return RoleHierarchyImpl.withDefaultRolePrefix()
                .role("ADMIN").implies("MODERADOR")
                .role("MODERADOR").implies("ESTUDANTE", "INSTRUTOR")
                .build();
    }
}
