package com.nadhem.livres.service;
import java.util.List;

import org.springframework.data.domain.Page;

import com.nadhem.livres.entities.Genre;

public interface GenreService {
	Genre saveGenre(Genre g);
	Genre updateGenre(Genre g);
	void deleteGenre(Genre g);
	Genre getGenreById(Long id);
	void deleteGenreById(Long id);
	List<Genre> getAllGenres();
	Page<Genre> getAllGenresParPage(int page, int size);

}
