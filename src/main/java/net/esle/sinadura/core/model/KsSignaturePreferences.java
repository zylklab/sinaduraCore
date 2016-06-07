package net.esle.sinadura.core.model;

import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;


/**
 * @author alfredo
 *
 */
public class KsSignaturePreferences {
	
	private KeyStore ks = null;
	private String alias = null;
	private PasswordProtection passwordProtection = null;
	
	public void setKs(KeyStore ks) {
		this.ks = ks;
	}
	public KeyStore getKs() {
		return ks;
	}
	public void setAlias(String alias) {
		this.alias = alias;
	}
	public String getAlias() {
		return alias;
	}
	public void setPasswordProtection(PasswordProtection passwordProtection) {
		this.passwordProtection = passwordProtection;
	}
	public PasswordProtection getPasswordProtection() {
		return passwordProtection;
	}
	
}
