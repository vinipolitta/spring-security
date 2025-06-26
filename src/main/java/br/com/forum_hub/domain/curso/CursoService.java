package br.com.forum_hub.domain.curso;

import br.com.forum_hub.infra.exception.RegraDeNegocioException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class CursoService {

    private final CursoRepository repository;

    public CursoService(CursoRepository repository) {
        this.repository = repository;
    }

    public Curso buscarPeloId(Long id) {
        return repository.findById(id).orElseThrow(() -> new RegraDeNegocioException("Curso não encontrado!"));
    }

    public Page<DadosCurso> listar(Categoria categoria, Pageable paginacao) {
        if (categoria != null)
            return repository.findByCategoria(categoria, paginacao).map(DadosCurso::new);
        return repository.findAll(paginacao).map(DadosCurso::new);

    }

    public Curso criar(DadosCurso dados) {
        Curso curso = new Curso(dados.nome(), dados.categoria());
        return repository.save(curso);
    }
}
