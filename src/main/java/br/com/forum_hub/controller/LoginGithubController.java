package br.com.forum_hub.controller;

import br.com.forum_hub.domain.autenticacao.DadosToken;
import br.com.forum_hub.domain.autenticacao.TokenService;
import br.com.forum_hub.domain.autenticacao.github.LoginGithubService;
import br.com.forum_hub.domain.usuario.Usuario;
import br.com.forum_hub.domain.usuario.UsuarioRepository;
import br.com.forum_hub.domain.usuario.UsuarioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/login/github")
public class LoginGithubController {

    @Autowired
    private LoginGithubService loginGithubService;

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private TokenService tokenService;

    @Autowired
    UsuarioService usuarioService;

    @GetMapping
    public ResponseEntity<Void> redirecionarGithub() {

        var url = loginGithubService.gerarUrl();

        var headers = new HttpHeaders();
        headers.setLocation(URI.create(url));

        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    @GetMapping("/autorizado")
    public ResponseEntity<DadosToken> autenticarUsuarioOAuth(@RequestParam String code) {

        var email = loginGithubService.obterEmail(code);

        var usuarioOptional = usuarioRepository.findByEmailIgnoreCaseAndVerificadoTrueAndAtivoTrue(email);

        if (usuarioOptional.isEmpty()) {
            throw new UsernameNotFoundException("Usuário não encontrado ou não verificado/ativo!");
        }

        var usuario = usuarioOptional.get();

        var authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String tokenAcesso = tokenService.gerarToken(usuario);
        String refreshToken = tokenService.gerarRefreshToken(usuario);

        return ResponseEntity.ok(new DadosToken(tokenAcesso, refreshToken, false));
    }



//novas urls de registro:


    @GetMapping("/registro")

    public ResponseEntity<Void> redirecionarRegistroGithub() {

        var url = loginGithubService.gerarUrl();
        var headers = new HttpHeaders();

        headers.setLocation(URI.create(url));

        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    @GetMapping("/registro-autorizado")

    public ResponseEntity<DadosToken> registrarOAuth(@RequestParam String code) {

        var dadosUsuario = loginGithubService.obterDadosOAuth(code);
        var usuario = usuarioService.cadastrarVerificado(dadosUsuario);
        var authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String tokenAcesso = tokenService.gerarToken(usuario);
        String refreshToken = tokenService.gerarRefreshToken(usuario);

        return ResponseEntity.ok(new DadosToken(tokenAcesso, refreshToken, false));

    }
}
