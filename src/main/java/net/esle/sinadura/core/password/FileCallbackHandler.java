package net.esle.sinadura.core.password;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.util.Properties;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class FileCallbackHandler implements CallbackHandler, PasswordExtractor {

	public static final String PASSWORD_CERTIFICATE = "certificate.password";
	
	private PasswordProtection passwordProtection = null;
	private String preferencesPath;
	
	
	public FileCallbackHandler(String preferencesPath) {
		
		this.preferencesPath = preferencesPath;
	}
	
	public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
		
		for (Callback c : callbacks) {
			
			if (c instanceof PasswordCallback) {
				
				PasswordCallback pc = (PasswordCallback) c;
				this.initPassword();

				if (this.passwordProtection != null) {
					
					if (this.passwordProtection.getPassword() != null) {
						
						pc.setPassword(this.passwordProtection.getPassword());
					}
				}
			}
		}
	}
	
	
	private void initPassword() throws IOException {
		
		Properties p = new Properties();
		p.load(new FileInputStream(this.preferencesPath));
		
		String pass = p.getProperty(PASSWORD_CERTIFICATE);
		
		this.passwordProtection = new KeyStore.PasswordProtection(pass.toCharArray());
	}
	
	public PasswordProtection getPasswordProtection() {

		return this.passwordProtection;
	}
}
