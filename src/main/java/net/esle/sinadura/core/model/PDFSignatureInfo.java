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


/**
 * 
 * @author alfredo
 *
 */
public class PDFSignatureInfo {

	private Status status;
	private String name;
	private ChainInfo chainInfo;
	private Date date;
	private ValidationError error;
	private TimestampInfo timestampInfo;

	public PDFSignatureInfo() {
		
		this.status = Status.VALID; // TODO esto al final asi?
		this.name = null;
		this.chainInfo = null;
		this.date = null;
		this.error = null;
		this.timestampInfo = null;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public void setDate(Date date) {
		this.date = date;
	}

	public Date getDate() {
		return date;
	}

	public void setTimestampInfo(TimestampInfo timestampInfo) {
		this.timestampInfo = timestampInfo;
	}

	public TimestampInfo getTimestampInfo() {
		return timestampInfo;
	}

	public void setChainInfo(ChainInfo chainInfo) {
		this.chainInfo = chainInfo;
	}

	public ChainInfo getChainInfo() {
		return chainInfo;
	}

	public void setError(ValidationError error) {
		this.error = error;
	}

	public ValidationError getError() {
		return error;
	}

	public void setStatus(Status status) {
		this.status = status;
	}

	public Status getStatus() {
		return status;
	}

	@Override
	public String toString() {
		return "chainInfo=" + chainInfo + "\ndate=" + date + ", error=" + error + ", name=" + name
				+ ", status=" + status + ", \ntimestampInfo=" + timestampInfo;
	}



}
