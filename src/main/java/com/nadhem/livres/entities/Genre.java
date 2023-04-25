package com.nadhem.livres.entities;

import java.util.Date;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "genre")
public class Genre {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id_gen")
	private Long idGen;
	
	@Column(name = "nom_gen")
	private String nomGen;
	

	@Column(name = "date_creation")
	private Date dateCreation;
	
	@JsonIgnore
	@OneToMany(mappedBy = "genre", cascade = CascadeType.ALL)
	private List<Livre> livres;
	
	public Long getIdGen() {
		return idGen;
	}

	public void setIdGen(Long idGen) {
		this.idGen = idGen;
	}

	public String getNomGen() {
		return nomGen;
	}

	public void setNomGen(String nomGen) {
		this.nomGen = nomGen;
	}

	public Date getDateCreation() {
		return dateCreation;
	}

	public void setDateCreation(Date dateCreation) {
		this.dateCreation = dateCreation;
	}

	public List<Livre> getLivres() {
		return livres;
	}

	public void setLivres(List<Livre> livres) {
		this.livres = livres;
	}

	
}
