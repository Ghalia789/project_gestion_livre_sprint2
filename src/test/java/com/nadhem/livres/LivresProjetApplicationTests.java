package com.nadhem.livres;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import com.nadhem.livres.entities.Livre;
import com.nadhem.livres.repos.LivreRepository;

@SpringBootTest
class LivresProjetApplicationTests {

	LivreRepository livreRepository;
	@Test
	public void findByTitreLivre()
	{
	List<Livre> livres = livreRepository.findByTitreLivre("iphone X");
	for (Livre l : livres) {
	System.out.println(l);
	} }
	@Test
	public void findByTitreLivreContains ()
	{
	 List<Livre> livres = livreRepository.findByTitreLivreContains("i");
	for (Livre l : livres) {
	System.out.println(l);
	} 
	}

}
