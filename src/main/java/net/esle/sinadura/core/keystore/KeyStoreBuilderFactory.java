 package net.esle.sinadura.core.keystore;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.security.auth.login.LoginException;

import net.esle.sinadura.core.exceptions.CoreException;
import net.esle.sinadura.core.exceptions.CorePKCS12Exception;
import net.esle.sinadura.core.exceptions.NoSunPkcs11ProviderException;
import net.esle.sinadura.core.password.DummyCallbackHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import sun.security.pkcs11.SunPKCS11;

public class KeyStoreBuilderFactory {
	
	private static final Log log = LogFactory.getLog(KeyStoreBuilderFactory.class);
	
	public static enum KeyStoreTypes { PKCS11, PKCS12 , MSCAPI};
	
	/* Codigos de estado del wraper al dispositivos pkcs11 */
	
	// errores relacionados con el PIN
	// TODO estas son propias de PKCS11Exception asi igual es mejor meterlas en dicha excepcion
	public final static String CKR_PIN_INCORRECT = "CKR_PIN_INCORRECT";
	public final static String CKR_PIN_INVALID = "CKR_PIN_INVALID";
	public final static String CKR_PIN_LEN_RANGE = "CKR_PIN_LEN_RANGE";
	public final static String CKR_PIN_EXPIRED = "CKR_PIN_EXPIRED";
	public final static String CKR_PIN_LOCKED = "CKR_PIN_LOCKED";
	
	// error general se produce cuando la tarjeta esta mal insertada o no esta insertada
	public final static String CKR_GENERAL_ERROR = "CKR_GENERAL_ERROR"; 
	
	// error sobre el puerto, implica que el lector esta mal configurado o que el demonio opensc esta inaccesible
	public final static String CKR_DEVICE_ERROR = "CKR_DEVICE_ERROR";
	
	
	public static KeyStore getKeyStore(String name, KeyStoreTypes type, String file, KeyStore.CallbackHandlerProtection callback)
			throws net.esle.sinadura.core.exceptions.PKCS11Exception, NoSunPkcs11ProviderException, NoSuchAlgorithmException, KeyStoreException, CoreException,
			CorePKCS12Exception {
		
		
		//el slot 0 no se usa realmente, sino que se sobreescribe en el case pkcs11 lo cual está mal planteado pero a nivel de orientacion
		//de codigo
		return getKeyStore(name, type, file, "0", callback);
	}
	

	public static KeyStore getKeyStore(String name, KeyStoreTypes type, String file, String slot,
			KeyStore.CallbackHandlerProtection callback) throws net.esle.sinadura.core.exceptions.PKCS11Exception, NoSunPkcs11ProviderException, 
			NoSuchAlgorithmException, KeyStoreException, CoreException, CorePKCS12Exception {
		
		KeyStore.Builder builder = null;
		KeyStore ks = null;
		
		switch (type) {
		case PKCS11:
			try {
				
				// Si existe el provider con el nombre que utilizo lo quito
				//String pkcs11config = "name = " + name + "\nlibrary =" + file + "\nshowInfo=false\nslotListIndex=" + slot;
				String pkcs11config = "name = " + name + "\nlibrary =" + file + "\nshowInfo=false\nslot=" + slot;
				InputStream confStream = new ByteArrayInputStream(pkcs11config.getBytes());

				Provider sunpkcs11 = (Provider) Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(InputStream.class).newInstance(confStream);

				// si no se ha añadido antes lo añado
				if (Security.getProvider(sunpkcs11.getName()) != null) { // la otra alternativa sería implementar un patron-singleton
					Security.removeProvider(sunpkcs11.getName());
				}
				Security.addProvider(sunpkcs11);
				try {
					builder = KeyStore.Builder.newInstance("PKCS11", sunpkcs11, callback);
				} catch (RuntimeException e) {
					throw new CoreException(e);
				}
				try {
					ks = builder.getKeyStore();
				} catch (KeyStoreException e) {
					Security.removeProvider(sunpkcs11.getName()); // si se produce un error elimino el provider del scope
					// Capturo la excepcion y busco el origen, para identificar si hay problemas con el dispositivo, con el pin de la
					// tarjeta etc...
					throwNestedException(e);
				}
				return ks;

			// NoSunPkcs11ProviderException
			}catch(NoClassDefFoundError e){
				e.printStackTrace();
				throw new NoSunPkcs11ProviderException();
			}catch(IllegalAccessException e){
				throw new NoSunPkcs11ProviderException();
			} catch (InstantiationException e1) {
				throw new NoSunPkcs11ProviderException();
			} catch (NoSuchMethodException e1) {
				throw new NoSunPkcs11ProviderException();
			} catch (ClassNotFoundException e1) {
				throw new NoSunPkcs11ProviderException();
				
				
			}catch(InvocationTargetException e){
				throwNestedException(e);
			} catch (RuntimeException e) {
				// capturo todas las excepciones de runtime a la hora de crear el keystore porque si el lector esta mal configurado o el
				// demonio opensc esta parado
				// o la tarjeta está mal insertada la excepcion que se genera es de runtime y enmscara un de tipo PKCS11
				throwNestedException(e);
			}
			
			
		case MSCAPI:

			//se delega el password callaback en el MSCAPI
			try {
				Provider msprovider = KeyStore.getInstance("Windows-MY").getProvider();
				//no se porque no está visible el SunMSCAPI
				//Provider msprovider = new sun.security.mscapi.SunMSCAPI();
				DummyCallbackHandler dummycallback = new DummyCallbackHandler(null);
				builder = KeyStore.Builder.newInstance("Windows-MY", msprovider, new KeyStore.CallbackHandlerProtection(dummycallback));
				ks = builder.getKeyStore();
				
				
			} catch (KeyStoreException e) {
				throwNestedException(e);
			}

			if (ks == null) {
				throw new CoreException(new Exception(""));
			}

			return ks;
			
			
		case PKCS12:

			try {
				builder = KeyStore.Builder.newInstance("PKCS12", null, new File(file), callback);
			} catch (RuntimeException e) {
				throw new CoreException(e);
			}

			try {
				ks = builder.getKeyStore();
			} catch (KeyStoreException e) {
				throwNestedException(e);
			}

			if (ks == null) {
				throw new CoreException(new Exception(""));
			}

			return ks;

		default:
			return null;
		}
	}
	
	private static void throwNestedException(Throwable e) throws net.esle.sinadura.core.exceptions.PKCS11Exception,
			NoSuchAlgorithmException, KeyStoreException, CoreException, CorePKCS12Exception {

		Throwable origin = e;
		Throwable cause = e;

		while (cause.getCause() != null) {
			cause = cause.getCause();
		}
		
		// una vez que he llegado a la excepción origen, la lanzo para no perder su información en la traza
		if (cause.getClass().getName().equals("sun.security.pkcs11.wrapper.PKCS11Exception")) {
			// esta la paso a una propia para no usar el API restringido de SUN 
			throw new net.esle.sinadura.core.exceptions.PKCS11Exception(cause.getMessage());
		} else if (cause.getClass().getName().equals("java.security.NoSuchAlgorithmException")) {
			throw (NoSuchAlgorithmException) cause;
		} else if (cause.getClass().getName().equals("java.security.ProviderException")) {
			throw new CoreException((ProviderException) cause);
		} else if (cause.getClass().getName().equals("java.io.IOException")) {
			throw new CoreException((IOException) cause);
		} else if (cause.getClass().getName().equals("javax.crypto.BadPaddingException")) {
			throw new CorePKCS12Exception((BadPaddingException) cause);
		}

		// si no es de tipo PKCS11 o NoSuchAlgorithmException devuelvo la de entrada
		if (origin.getClass().getName().equals("java.security.KeyStoreException")) {
			throw (KeyStoreException) origin;
		} else if (origin.getClass().getName().equals("java.lang.RuntimeException")) {
			throw (RuntimeException) origin;
		} else {
			throw new RuntimeException (origin);
		}

	}
	
	// TODO logout del keystore o del provider????
	public static void logout(KeyStore ks) throws NoSunPkcs11ProviderException
	{
		logout(ks, null);
	}
	public static void logout(KeyStore ks, String alias) throws NoSunPkcs11ProviderException
	{
		if (ks != null) {
			try {
				((SunPKCS11) ks.getProvider()).logout();
				log.info("logout pkcs11");
			}catch(NoClassDefFoundError e){
				throw new NoSunPkcs11ProviderException();
				
			} catch (ClassCastException e) {
				log.info("no es necesario hacer logout con PKCS12, o MSCAPI");
			} catch (LoginException e) {
				log.error("logout exception", e);
			} catch (RuntimeException e) {
				log.error("logout exception", e);
			}
		}
	}
	
}








