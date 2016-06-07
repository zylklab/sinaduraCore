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
 * @author alfredo
 *
 */
public class ConsoleCallbackHandler implements CallbackHandler, PasswordExtractor {
	
	private PasswordProtection passwordProtection = null;
	
	
	public ConsoleCallbackHandler(String preferencesPath) {
		
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

	
	private void initPassword() {
		
		System.out.print("Enter your PIN: ");
		// open up standard input
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

		String pin_s = null;
		try {
			pin_s = br.readLine();
		} catch (IOException ioe) {
			System.out.println("IO error trying to read the PIN");
			System.exit(1);
		}
				
		this.passwordProtection = new KeyStore.PasswordProtection(pin_s.toCharArray());
	}
	
	public PasswordProtection getPasswordProtection() {

		return this.passwordProtection;
	}
	
	
}
