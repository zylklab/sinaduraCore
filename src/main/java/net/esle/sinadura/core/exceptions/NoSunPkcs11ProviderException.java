package net.esle.sinadura.core.exceptions;

public class NoSunPkcs11ProviderException extends Exception {
	
	@Override
	public String toString(){
		return "No se ha encontrado el proveedor 'sun.security.pkcs11.SunPKCS11' en la instalación Java, con lo que no se podrá firmar.";
	}
}
