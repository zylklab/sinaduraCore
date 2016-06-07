package net.esle.sinadura.core.exceptions;

/**
 * Error generico al realizar ocsp
 * 
 * @author alfredo
 *
 */
public class OCSPCoreException extends Exception {
	
	public OCSPCoreException(Exception e) {
		super(e);
	}
	
	public OCSPCoreException(String arg0) {
		super(arg0);
	}
}
