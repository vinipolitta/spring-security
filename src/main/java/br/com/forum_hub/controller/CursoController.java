package br.com.forum_hub.controller;

import br.com.forum_hub.domain.curso.Categoria;
import br.com.forum_hub.domain.curso.Curso;
import br.com.forum_hub.domain.curso.CursoService;
import br.com.forum_hub.domain.curso.DadosCurso;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/cursos")
public class CursoController {

    private final CursoService service;

    public CursoController(CursoService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<Page<DadosCurso>> listar(@RequestParam(required = false) Categoria categoria,
                                                   @PageableDefault(size = 10, sort = {"nome"}) Pageable paginacao){
        var pagina = service.listar(categoria, paginacao);
        return ResponseEntity.ok(pagina);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<Curso> criarCurso(@RequestBody DadosCurso curso) {
        Curso novoCurso = service.criar(curso);
        return ResponseEntity.ok(novoCurso);
    }

}
