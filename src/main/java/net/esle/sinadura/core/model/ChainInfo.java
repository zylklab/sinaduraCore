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
import java.util.Date;
import java.util.List;


public class ChainInfo {

	private Status status;
	private List<X509Certificate> chain;
	private Date date;
	private Error error;
	private int index;
	private String log; // solo para los genericos de sun

	public enum Error {
		 
		INCOMPLETE,
		EXPIRED,
		NOTYETVALID,
		REVOCATION_UNKNOWN, // error generico para las ocsp
		REVOKED,
		GENERIC, // error generico (los de sun)
		UNTRUST,
	}
	
	public ChainInfo() {
		
		this.status = Status.UNKNOWN;
		this.chain = null;
		this.date = null;
		this.error = null;
		this.index = 0;
		this.log = null;
	}

	public List<X509Certificate> getChain() {
		return chain;
	}

	public void setChain(List<X509Certificate> chain) {
		this.chain = chain;
	}

	public Error getError() {
		return error;
	}

	public void setError(Error error) {
		this.error = error;
	}

	public int getIndex() {
		return index;
	}

	public void setIndex(int index) {
		this.index = index;
	}

	public String getLog() {
		return log;
	}

	public void setLog(String log) {
		this.log = log;
	}

	public void setStatus(Status status) {
		this.status = status;
	}

	public Status getStatus() {
		return status;
	}

	public void setDate(Date date) {
		this.date = date;
	}

	public Date getDate() {
		return date;
	}

	@Override
	public String toString() {
		return chain.get(0).getSubjectDN() + "\ndate=" + date + ", error=" + error + ", index=" + index + ", log=" + log + ", status="
				+ status;
	}
	
	

}

