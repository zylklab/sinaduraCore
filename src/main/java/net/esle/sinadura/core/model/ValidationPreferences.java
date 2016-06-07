package net.esle.sinadura.core.model;

import java.security.KeyStore;


/**
 * Configuracion para los proceso de validacion.
 *
 */
public class ValidationPreferences {
	
	private boolean checkRevocation = true;
	private KeyStore ksCache = null;
	private KeyStore ksTrust = null;
	private boolean validateEpesPolicy = true;
 

	public void setCheckRevocation(boolean checkRevocation) {
		this.checkRevocation = checkRevocation;
	}

	public boolean isCheckRevocation() {
		return checkRevocation;
	}

	public void setKsCache(KeyStore ksCache) {
		this.ksCache = ksCache;
	}

	public KeyStore getKsCache() {
		return ksCache;
	}

	public void setKsTrust(KeyStore ksTrust) {
		this.ksTrust = ksTrust;
	}

	public KeyStore getKsTrust() {
		return ksTrust;
	}

	public void setValidateEpesPolicy(boolean validateEpesPolicy) {
		this.validateEpesPolicy = validateEpesPolicy;
	}

	public boolean isValidateEpesPolicy() {
		return validateEpesPolicy;
	}

	
		
}
