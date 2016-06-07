package net.esle.sinadura.core.model;

import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;


/**
 * @author alfredo
 *
 */
public class SignaturePreferences {
	
	// TODO añadir inputs aqui!!!
	
	// Hay dos opciones a la hora de firmar:
	// 1- Se indicar el keystore y el alias, de forma que en la accion de firma se obtiene la privateKey.
	private KsSignaturePreferences ksSignaturePreferences = null;
	// 2- Se indica directamente la privateKey, obtenida previamente (cryptoApplet).
	private Provider provider = null;
	private PrivateKey privateKey = null;
	private X509Certificate certificate = null;
	
	private KeyStore ksCache = null;
	private String timestampUrl = null;
	private String timestampUser = null;
	private String timestampPassword = null;
	private String timestampOcspUrl = null;
	private boolean addOCSP = true;
	
	
	public SignaturePreferences() {
		this.ksSignaturePreferences = new KsSignaturePreferences();
	}
	
	public void setTimestampUrl(String timestampUrl) {
		this.timestampUrl = timestampUrl;
	}
	public String getTimestampUrl() {
		return timestampUrl;
	}
	public void setAddOCSP(boolean addOCSP) {
		this.addOCSP = addOCSP;
	}
	public boolean getAddOCSP() {
		return addOCSP;
	}
	public void setKsCache(KeyStore ksCache) {
		this.ksCache = ksCache;
	}
	public KeyStore getKsCache() {
		return ksCache;
	}
	public void setTimestampUser(String timestampUser) {
		this.timestampUser = timestampUser;
	}
	public String getTimestampUser() {
		return timestampUser;
	}
	public void setTimestampPassword(String timestampPassword) {
		this.timestampPassword = timestampPassword;
	}
	public String getTimestampPassword() {
		return timestampPassword;
	}
	public void setKsSignaturePreferences(KsSignaturePreferences ksSignaturePreferences) {
		this.ksSignaturePreferences = ksSignaturePreferences;
	}
	public KsSignaturePreferences getKsSignaturePreferences() {
		return ksSignaturePreferences;
	}
	public void setTimestampOcspUrl(String timestampOcspUrl) {
		this.timestampOcspUrl = timestampOcspUrl;
	}
	public String getTimestampOcspUrl() {
		return timestampOcspUrl;
	}
	public Provider getProvider() {
		return provider;
	}
	public void setProvider(Provider provider) {
		this.provider = provider;
	}
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public X509Certificate getCertificate() {
		return certificate;
	}

	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}

}
