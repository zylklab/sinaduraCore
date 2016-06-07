package net.esle.sinadura.core.password;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;


/**
 * @author gustavo
 *	
 */
public class DummyCallbackHandler implements CallbackHandler, PasswordExtractor {
	
	private PasswordProtection passwordProtection = null;
	
	
	public DummyCallbackHandler(String preferencesPath) {
		this.initPassword();
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

	
	private void initPassword() 
	{
		String pin_s = null;
		pin_s = "dummy";
		this.passwordProtection = new KeyStore.PasswordProtection(pin_s.toCharArray());
	}
	
	public PasswordProtection getPasswordProtection() {

		return this.passwordProtection;
	}
	
	
}
