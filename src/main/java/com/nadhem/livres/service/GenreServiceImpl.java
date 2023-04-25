package com.nadhem.livres.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.nadhem.livres.entities.Genre;
import com.nadhem.livres.entities.Livre;
import com.nadhem.livres.repos.GenreRepository;
import com.nadhem.livres.repos.LivreRepository;

@Service
public class GenreServiceImpl implements GenreService{

	
	@Autowired
	GenreRepository genreRepository;
	
	@Override
	public Genre saveGenre(Genre g) {
		return genreRepository.save(g);
	}

	@Override
	public Genre updateGenre(Genre g) {
		return genreRepository.save(g);
	}

	@Override
	public void deleteGenre(Genre g) {
		genreRepository.delete(g);
	}

	@Override
	public Genre getGenreById(Long id) {
		return genreRepository.findById(id).get();
	}

	@Override
	public List<Genre> getAllGenres() {
		return genreRepository.findAll();
	}
	
	@Override
	public Page<Genre> getAllGenresParPage(int page, int size){
		return genreRepository.findAll(PageRequest.of(page, size));

	}

	@Override
	public void deleteGenreById(Long id) {
		genreRepository.deleteById(id);

	}

}
