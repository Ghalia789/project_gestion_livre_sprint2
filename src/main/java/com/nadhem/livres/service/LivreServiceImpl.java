package com.nadhem.livres.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.nadhem.livres.entities.Genre;
import com.nadhem.livres.entities.Livre;
import com.nadhem.livres.repos.LivreRepository;

@Service
public class LivreServiceImpl implements LivreService{

	@Autowired
	LivreRepository livreRepository;
	
	@Override
	public Livre saveLivre(Livre p) {
		return livreRepository.save(p);
	}

	@Override
	public Livre updateLivre(Livre p) {
		return livreRepository.save(p);
	}

	@Override
	public void deleteLivre(Livre p) {
		livreRepository.delete(p);
	}

	@Override
	public void deleteLivreById(Long id) {
		livreRepository.deleteById(id);
	}

	@Override
	public Livre getLivre(Long id) {
		return livreRepository.findById(id).get();
	}

	@Override
	public List<Livre> getAllLivres() {
		return livreRepository.findAll();
	}

	@Override
	public Page<Livre> getAllLivresParPage(int page, int size) {
		return livreRepository.findAll(PageRequest.of(page, size));
	}

	@Override
	public List<Livre> getLivresByGenre(Genre genre) {
		return livreRepository.findByGenre(genre);
	}

	@Override
	public List<Livre> findByGenreIdGen(Long idGen) {
		
		return livreRepository.findByGenreIdGen(idGen);
	}

}
