package com.nadhem.livres.service;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

import com.nadhem.livres.entities.Genre;
import com.nadhem.livres.entities.Livre;

public interface LivreService {
	Livre saveLivre(Livre p);
	Livre updateLivre(Livre p);
	void deleteLivre(Livre p);
	 void deleteLivreById(Long id);
	 Livre getLivre(Long id);
	List<Livre> getAllLivres();
	Page<Livre> getAllLivresParPage(int page, int size);
	List<Livre> getLivresByGenre(Genre genre);
	List<Livre>findByGenreIdGen(Long idGen);
}
