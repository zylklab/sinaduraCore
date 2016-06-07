package net.esle.sinadura.core.model;


/**
 * @author alfredo
 *
 */
public class XadesSignaturePreferences extends SignaturePreferences {
	
	public enum Type {
		Detached
	}
	
	private Type type;
	private boolean archive;
	private boolean xlOcspAddAll;
	
	public Type getType() {
		return type;
	}

	public void setType(Type type) {
		this.type = type;
	}

	/**
	 * true para empaquetar la firma en un SAR.
	 * 
	 * @param archive
	 */
	public void setGenerateArchiver(boolean archive) {
		this.archive = archive;
	}

	public boolean isGenerateArchiver() {
		return archive;
	}

	public void setXlOcspAddAll(boolean xlOcspAddAll) {
		this.xlOcspAddAll = xlOcspAddAll;
	}

	public boolean isXlOcspAddAll() {
		return xlOcspAddAll;
	}
	
}
