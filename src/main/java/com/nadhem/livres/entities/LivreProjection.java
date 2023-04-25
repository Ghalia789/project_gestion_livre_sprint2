package com.nadhem.livres.entities;

import org.springframework.data.rest.core.config.Projection;
@Projection(name = "titreLivre", types = { Livre.class })
public interface LivreProjection {
	public String getTitreLivre();
}
