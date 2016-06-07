package net.esle.sinadura.core.password;

import java.security.KeyStore.PasswordProtection;

/**
 * @author alfredo
 * 
 * To get the password from a PasswordCallbackHandler implementation, 
 * otherwise it is requiered two password petitions to sign a single pdf.
 *
 */
public interface PasswordExtractor {
	
	
	public PasswordProtection getPasswordProtection();
}
