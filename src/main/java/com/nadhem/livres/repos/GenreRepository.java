package com.nadhem.livres.repos;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.nadhem.livres.entities.Genre;

@Repository
public interface GenreRepository extends JpaRepository<Genre, Long>{

}
