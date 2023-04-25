package com.nadhem.livres.controllers;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.nadhem.livres.entities.Genre;
import com.nadhem.livres.entities.Livre;
import com.nadhem.livres.service.GenreService;
import com.nadhem.livres.service.LivreService;

@Controller
public class GenreController {
	
	@Autowired
	private GenreService genreService;
	
	@Autowired
    private LivreService livreService;

   
	@GetMapping("/showCreateGenre")
	public String showCreate(ModelMap model) {
		model.addAttribute("genre", new Genre());
		return "createGenre";
	}

	/*@PostMapping("/saveGenre")
	public String saveGenre(@ModelAttribute("genre") Genre genre, BindingResult result,
			@RequestParam("dateCreation") String dateCreation, ModelMap modelMap) throws ParseException {
		
		if (result.hasErrors()) {
			return "createGenre";
		}
		
		// conversion de la date
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
		Date date = dateFormat.parse(dateCreation);
		genre.setDateCreation(date);

		Genre savedGenre = genreService.saveGenre(genre);
		String msg = "Genre enregistré avec Id " + savedGenre.getIdGen();
		modelMap.addAttribute("msg", msg);
		return "redirect:listeGenres";
	}*/

	@GetMapping("/listeGenres")
	public String listeGenres(ModelMap modelMap, @RequestParam(name = "page", defaultValue = "0") int page,
			@RequestParam(name = "size", defaultValue = "3") int size) {
		Page<Genre> genres = genreService.getAllGenresParPage(page, size);
		modelMap.addAttribute("genres", genres);
		modelMap.addAttribute("pages", new int[genres.getTotalPages()]);
		modelMap.addAttribute("currentPage", page);
		modelMap.addAttribute("size", size);
		return "listeGenres";
	}

	@GetMapping("/supprimerGenre")
	public String supprimerGenre(@RequestParam("id") Long id, ModelMap modelMap,
			@RequestParam(name = "page", defaultValue = "0") int page,
			@RequestParam(name = "size", defaultValue = "2") int size) {
		genreService.deleteGenreById(id);
		Page<Genre> genres = genreService.getAllGenresParPage(page, size);
		modelMap.addAttribute("genres", genres);
		modelMap.addAttribute("pages", new int[genres.getTotalPages()]);
		modelMap.addAttribute("currentPage", page);
		modelMap.addAttribute("size", size);
		return "listeGenres";
	}

	@GetMapping("/modifierGenre")
	public String editerGenre(@RequestParam("id") Long id, ModelMap modelMap) {
		Genre genre = genreService.getGenreById(id);
		modelMap.addAttribute("genre", genre);
		return "editerGenre";
	}

	/*@PostMapping("/updateGenre")
	public String updateGenre(@ModelAttribute("genre") Genre genre, BindingResult result,
			@RequestParam("dateCreation") String dateCreation, ModelMap modelMap) throws ParseException {
		
		if (result.hasErrors()) {
			return "editerGenre";
		}
		
		// conversion de la date
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
		Date date = dateFormat.parse(dateCreation);
		genre.setDateCreation(date);

		genreService.saveGenre(genre);
		String msg = "Genre modifié+ avec succès";
		modelMap.addAttribute("msg", msg);
		return "redirect:/genres";
	}

	// Méthode pour supprimer un genre
	@GetMapping("/deleteGenre/{id}")
	public String deleteGenre(@PathVariable("id") Long id, ModelMap modelMap) {
		genreService.deleteGenreById(id);
		String msg = "Genre supprimé avec succès.";
		modelMap.addAttribute("msg", msg);
		
		return "redirect:/genres";
	}

	 // Méthode pour afficher les livres d'un genre donné
    @GetMapping("/{id}/livres")
    public String showLivresByGenre(@PathVariable("id") Long id, ModelMap modelMap) {
        Genre genre = genreService.getGenreById(id);
        List<Livre> livres = livreService.getLivresByGenre(genre);
        modelMap.addAttribute("genre", genre);
        modelMap.addAttribute("livres", livres);

        return "livresParGenre";
    }*/

}
			