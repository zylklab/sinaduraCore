package net.esle.sinadura.core.model;

public class DataFile {

	private String digestType;
	private String digestValue;
	private String filename;
	
	public void setDigestType(String digestType) {
		this.digestType = digestType;
	}
	public String getDigestType() {
		return digestType;
	}
	public void setDigestValue(String digestValue) {
		this.digestValue = digestValue;
	}
	public String getDigestValue() {
		return digestValue;
	}
	public void setFilename(String filename) {
		this.filename = filename;
	}
	public String getFilename() {
		return filename;
	}

}


