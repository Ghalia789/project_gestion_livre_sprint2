package com.nadhem.livres.repos;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.stereotype.Repository;

import com.nadhem.livres.entities.Genre;
import com.nadhem.livres.entities.Livre;

/*@Repository*/
@RepositoryRestResource(path = "rest")
public interface LivreRepository extends JpaRepository<Livre, Long> {

	List<Livre> findByGenre(Genre genre);
	List<Livre> findByTitreLivre(String titreLivre);
	 List<Livre> findByTitreLivreContains(String titreLivre);
	 List<Livre> findByGenreIdGen(Long idGen);
}
