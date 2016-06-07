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

import java.util.Date;


public class TimestampInfo {
	
	private Status status;
	private ChainInfo chainInfo;
	private Date date;
	private Error error;
	
	public enum Error {
		
		CORRUPT,
		SIGNER_NOT_FOUND,
		CHAIN_ERROR,
	}
	
	public TimestampInfo () {
		
		this.status = Status.INVALID;
		this.chainInfo = null;
		this.error = null;
	}

	public Error getError() {
		return error;
	}

	public void setError(Error error) {
		this.error = error;
	}

	public void setChainInfo(ChainInfo chainInfo) {
		this.chainInfo = chainInfo;
	}

	public ChainInfo getChainInfo() {
		return chainInfo;
	}

	public void setStatus(Status status) {
		this.status = status;
	}

	public Status getStatus() {
		return status;
	}

	@Override
	public String toString() {
		return "chainInfo=" + chainInfo + "\nerror=" + error + ", status=" + status + "]";
	}

	public void setDate(Date date) {
		this.date = date;
	}

	public Date getDate() {
		return date;
	}
	
	

}

