package com.nadhem.livres.entities;

import java.time.LocalDate;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
public class Livre {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id_livre")
	private Long idLivre;
	
	@NotNull
	@Size (min = 1,max = 30)
	@Column(name = "titre_livre")
	private String titreLivre;
	
	@NotNull
	@Size (min = 1,max = 30)
	@Column(name = "auteur_livre")
	private String auteurLivre;
	
	@Min(value = 1)
	 @Max(value = 1000)
	@Column(name = "prix_livre")
	private Double prixLivre;
	
	
	@Column(name = "quantite_stock")
	private Integer quantiteStock;
	
	@Column(name = "date_publication")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date datePublication;

	@ManyToOne
	@JoinColumn(name="genre_id_gen")
	private Genre genre;


	public Livre() {
		super();
	}

	public Livre(String titreLivre, String auteurLivre, Double prixLivre, Integer quantiteStock, Date datePublication,
			Genre genre) {
		super();
		this.titreLivre = titreLivre;
		this.auteurLivre = auteurLivre;
		this.prixLivre = prixLivre;
		this.quantiteStock = quantiteStock;
		this.datePublication = datePublication;
		this.genre = genre;
	}

	public Long getIdLivre() {
		return idLivre;
	}

	public void setIdLivre(Long idLivre) {
		this.idLivre = idLivre;
	}

	public String getTitreLivre() {
		return titreLivre;
	}

	public void setTitreLivre(String titreLivre) {
		this.titreLivre = titreLivre;
	}

	public String getAuteurLivre() {
		return auteurLivre;
	}

	public void setAuteurLivre(String auteurLivre) {
		this.auteurLivre = auteurLivre;
	}

	public Double getPrixLivre() {
		return prixLivre;
	}

	public void setPrixLivre(Double prixLivre) {
		this.prixLivre = prixLivre;
	}

	public Date getDatePublication() {
		return datePublication;
	}

	public void setDatePublication(Date date) {
		this.datePublication = date;
	}

	public Integer getQuantiteStock() {
		return quantiteStock;
	}

	public void setQuantiteStock(Integer quantiteStock) {
		this.quantiteStock = quantiteStock;
	}

	public Genre getGenre() {
		return genre;
	}

	public void setGenre(Genre genre) {
		this.genre = genre;
	}

	@Override
	public String toString() {
		return "Livre{" + "idLivre=" + idLivre + ", titreLivre='" + titreLivre + '\'' + ", auteurLivre='"
				+ auteurLivre + '\'' + ", prixLivre=" + prixLivre + ", quantiteStock=" + quantiteStock
				+ ", datePublication=" + datePublication + ", genre=" + genre + '}';
	}
}
