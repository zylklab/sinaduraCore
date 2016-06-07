package net.esle.sinadura.console.utils;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;

import net.esle.sinadura.console.controllers.SignController;
import net.esle.sinadura.console.exceptions.ConsolePreferencesException;
import net.esle.sinadura.console.exceptions.PasswordCallbackException;
import net.esle.sinadura.console.exceptions.ValidationResultInvalidException;
import net.esle.sinadura.core.exceptions.ConnectionException;
import net.esle.sinadura.core.exceptions.CoreException;
import net.esle.sinadura.core.exceptions.CorePKCS12Exception;
import net.esle.sinadura.core.exceptions.NoSunPkcs11ProviderException;
import net.esle.sinadura.core.exceptions.OCSPCoreException;
import net.esle.sinadura.core.exceptions.OCSPIssuerRequiredException;
import net.esle.sinadura.core.exceptions.OCSPUnknownUrlException;
import net.esle.sinadura.core.exceptions.PKCS11Exception;
import net.esle.sinadura.core.exceptions.PdfSignatureException;
import net.esle.sinadura.core.exceptions.RevokedException;
import net.esle.sinadura.core.exceptions.ValidationFatalException;
import net.esle.sinadura.core.exceptions.XadesSignatureException;
import net.esle.sinadura.core.exceptions.XadesValidationFatalException;
import net.esle.sinadura.core.keystore.KeyStoreBuilderFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class ExitCodeManagerUtils {

	public static final int EXIT_OK 							= 0;
	
	public static final int EXIT_ERR_PREFERENCES				= 10;
	
	public static final int EXIT_ERR_CERT 						= 20;
	public static final int EXIT_ERR_CERT_INVALID_PIN 			= 21;
	public static final int EXIT_ERR_CARD_BLOCKED 				= 22;
	
	
	public static final int EXIT_ERR_SIGN				 		= 30;
	public static final int EXIT_ERR_SIGN_CERT_EXPIRED			= 31;
	public static final int EXIT_ERR_SIGN_CERT_REVOKED			= 32;
	public static final int EXIT_ERR_SIGN_CERT_NOT_YET_VALID	= 33;
	

	public static final int EXIT_ERR_VALIDATION 				= 40;
	public static final int EXIT_ERR_VALIDATION_INVALID 		= 41;
	
	
	public static final int EXIT_ERR_SYSTEM 					= 255;
	
	
	private static Log log = LogFactory.getLog(SignController.class);
	
	
	public static int getExitCode(Throwable e){
		
		// log
		log.error(e);
		System.err.println(e.toString());
		e.printStackTrace();
		
		

		//-------------------------------------
		// EXIT_ERR_PREFERENCES
		//-------------------------------------
		if (
				e instanceof ConsolePreferencesException |
				e instanceof PasswordCallbackException
			){
			return EXIT_ERR_PREFERENCES;
		
			
		//-------------------------------------
		// EXIT_ERR_CERTIFICADO
		//-------------------------------------
		}else if (	
					e instanceof NoSunPkcs11ProviderException | 
					e instanceof PKCS11Exception | 
					e instanceof CorePKCS12Exception | 
					e instanceof KeyStoreException | 
					e instanceof NoSuchAlgorithmException |
					e instanceof CoreException){
			
			String cause = e.getCause().getMessage();
			if (
					e instanceof CorePKCS12Exception | 
					cause.equals(KeyStoreBuilderFactory.CKR_PIN_INCORRECT)){
				return EXIT_ERR_CERT_INVALID_PIN;
				
			}else if(cause.equals(KeyStoreBuilderFactory.CKR_PIN_LOCKED)){
				return EXIT_ERR_CARD_BLOCKED;
				
			}else{
				return EXIT_ERR_CERT;				
			}

			
		//-------------------------------------
		// EXIT_ERR_FIRMA
		//-------------------------------------			
		}else if (	
					e instanceof PdfSignatureException |
					e instanceof XadesSignatureException |
					e instanceof RevokedException | 
					e instanceof ConnectionException |
					e instanceof OCSPIssuerRequiredException |
					e instanceof OCSPUnknownUrlException |
					e instanceof CertificateExpiredException |
					e instanceof CertificateNotYetValidException |
					e instanceof XadesSignatureException |
					e instanceof OCSPCoreException){
			
			
			if (e instanceof RevokedException ){
				return EXIT_ERR_SIGN_CERT_REVOKED;
				
			}else if (
					e instanceof CertificateExpiredException){
				return EXIT_ERR_SIGN_CERT_EXPIRED;
				
			}else if (
					e instanceof CertificateNotYetValidException ){
				
				return EXIT_ERR_SIGN_CERT_NOT_YET_VALID;
				
			}else if (	e instanceof ConnectionException |
						e instanceof OCSPUnknownUrlException |
					 	e instanceof OCSPIssuerRequiredException |
					 	e instanceof OCSPCoreException
					 	){
				return EXIT_ERR_SIGN;
				
			}else{
				return EXIT_ERR_SIGN;	
			}

		//-------------------------------------
		// EXIT_ERR_VALIDACION
		//-------------------------------------
		}else if (
					e instanceof ValidationFatalException |
					e instanceof XadesValidationFatalException |
					e instanceof ValidationResultInvalidException
				){
			
			if (e instanceof ValidationResultInvalidException){
				return EXIT_ERR_VALIDATION_INVALID;
				
			}else{
				return EXIT_ERR_VALIDATION;				
			}
			
			
		//-------------------------------------
		// EXIT_ERR_SYSTEM
		//-------------------------------------			
		}else if (
				e instanceof FileNotFoundException |
				e instanceof IllegalArgumentException |
				e instanceof IOException |
				e instanceof Exception | 
				e instanceof Throwable){
			return EXIT_ERR_SYSTEM;
			
		}else{
			return EXIT_ERR_SYSTEM;
		}
	}
}
