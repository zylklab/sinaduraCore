/*
 * # Copyright 2008 zylk.net 
 * # 
 * # This file is part of Sinadura. 
 * # 
 * # Sinadura is free software: you can redistribute it and/or modify 
 * # it under the terms of the GNU General Public License as published by 
 * # the Free Software Foundation, either version 2 of the License, or 
 * # (at your option) any later version. 
 * # 
 * # Sinadura is distributed in the hope that it will be useful, 
 * # but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * # GNU General Public License for more details. 
 * # 
 * # You should have received a copy of the GNU General Public License 
 * # along with Sinadura. If not, see <http://www.gnu.org/licenses/>. [^] 
 * # 
 * # See COPYRIGHT.txt for copyright notices and details. 
 * #
 */
package net.esle.sinadura.core.model;

import java.security.cert.X509Certificate;
import java.util.List;

import es.mityc.firmaJava.libreria.xades.ResultadoValidacion;

/**
 * Como en el validador de la libreria no se comprueba el estado de revocacion de los certificados en firmas BES... hay que ampliar
 * tanto la implementacion de validacion como el modelo.
 * 
 * Tambien se añade la cadena completa del timestamp
 * 
 * @author alfredo
 * 
 */
public class XadesSignatureInfo extends ResultadoValidacion { 

	private ChainInfo chainInfo;
	// por el momento solo la chain del ts, no se hace validacion
	private List<X509Certificate> tsChain;
	

	public XadesSignatureInfo() {
		super();
		this.setChainInfo(null);
		this.setTsChain(null);
	}

	public void setChainInfo(ChainInfo chainInfo) {
		this.chainInfo = chainInfo;
	}

	public ChainInfo getChainInfo() {
		return chainInfo;
	}

	@Override
	public String toString() {
		return "chainInfo=" + chainInfo;
	}

	public void setTsChain(List<X509Certificate> tsChain) {
		this.tsChain = tsChain;
	}

	public List<X509Certificate> getTsChain() {
		return tsChain;
	}

}
