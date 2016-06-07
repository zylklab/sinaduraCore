package net.esle.sinadura.console.controllers;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;

import javax.security.auth.callback.CallbackHandler;

import net.esle.sinadura.console.exceptions.ConsolePreferencesException;
import net.esle.sinadura.console.exceptions.PasswordCallbackException;
import net.esle.sinadura.console.utils.PreferencesUtil;
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
import net.esle.sinadura.core.exceptions.XadesSignatureException;
import net.esle.sinadura.core.keystore.KeyStoreBuilderFactory;
import net.esle.sinadura.core.keystore.KeyStoreBuilderFactory.KeyStoreTypes;
import net.esle.sinadura.core.keystore.PKCS11Helper;
import net.esle.sinadura.core.model.PdfSignaturePreferences;
import net.esle.sinadura.core.model.XadesSignaturePreferences;
import net.esle.sinadura.core.password.DummyCallbackHandler;
import net.esle.sinadura.core.password.PasswordExtractor;
import net.esle.sinadura.core.service.PdfService;
import net.esle.sinadura.core.service.XadesService;
import net.esle.sinadura.core.util.FileUtil;
import net.esle.sinadura.core.util.KeystoreUtil;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.itextpdf.text.BadElementException;
import com.itextpdf.text.Image;

public class SignController {
	
	public static PasswordProtection passwordProtection = null;
	
	private static Log log = LogFactory.getLog(SignController.class);
	
	public static KeyStore loadKeyStore() throws PasswordCallbackException, NoSuchAlgorithmException,
			KeyStoreException, PKCS11Exception, NoSunPkcs11ProviderException, CoreException, CorePKCS12Exception{

		KeyStore ks = null;

		String passwordCallbackHandler = PreferencesUtil.getString(PreferencesUtil.PASSWORD_CALLBACK_HANDLER);

		String certType = PreferencesUtil.getString(PreferencesUtil.CERT_TYPE);
		String hardwarePath = PreferencesUtil.getString(PreferencesUtil.HARDWARE_DISPOSITIVE);
		String softwarePath = PreferencesUtil.getString(PreferencesUtil.SOFTWARE_DISPOSITIVE);

			Object o;
			try {
				o = Class.forName(passwordCallbackHandler).getConstructor(new Class[] { String.class }).newInstance(
						new Object[] { PreferencesUtil.getString(PreferencesUtil.PREFERENCES_PATH) });
			} catch (Exception e) {
				throw new PasswordCallbackException(e);
			}
			

		if (certType.equalsIgnoreCase(PreferencesUtil.CERT_TYPE_VALUE_HARDWARE)) {

			//como est tipo pkcs11 puede ser que la tarjeta no esté pinchada en el slot 0, por tanto vamos a comprobar primero en que slot está
			// y se lo vamaos a pasar a la factoria.
			
			long[] slots = null;
			String slot = "0";
			// primera aproximacion cargo el primer slot que tiene tarjeta insetada para el caso del controller de shell ya que no hay parametro
			// para este tema
			PKCS11Helper pk11h = new PKCS11Helper(hardwarePath, "");
			slots = pk11h.getSignatureCapableSlots();
			
			if(slots != null && slots.length > 0)
			{
				slot = slots[0]+"";
			}
			
			ks = KeyStoreBuilderFactory.getKeyStore("HARD", KeyStoreTypes.PKCS11, hardwarePath, slot, new KeyStore.CallbackHandlerProtection(
					(CallbackHandler) o));

		} else if (certType.equalsIgnoreCase(PreferencesUtil.CERT_TYPE_VALUE_SOFTWARE)) {

			ks = KeyStoreBuilderFactory.getKeyStore("SOFT", KeyStoreTypes.PKCS12, softwarePath, new KeyStore.CallbackHandlerProtection(
					(CallbackHandler) o));

		} else if (certType.equalsIgnoreCase(PreferencesUtil.CERT_TYPE_VALUE_MSCAPI)) {
			
			o = new DummyCallbackHandler(null);
			ks = KeyStoreBuilderFactory.getKeyStore("MSCAPI", KeyStoreTypes.MSCAPI, null, new KeyStore.CallbackHandlerProtection(
					(CallbackHandler) o));

		} 

		// fijo el passwordprotection para el PKCS12, para el PKCS11 no es
		// necesario pero por coherencia lo uso tambien.
		passwordProtection = ((PasswordExtractor) o).getPasswordProtection();
		return ks;

	}
	
	public static PdfSignaturePreferences setPdfProperties(KeyStore ks) throws KeyStoreException {

		PdfSignaturePreferences pdfSignaturePreferences = new PdfSignaturePreferences();
		String ksCache = PreferencesUtil.getString(PreferencesUtil.KS_CACHE);
		String ksCachePass = PreferencesUtil.getString(PreferencesUtil.KS_CACHE_PASS);

		pdfSignaturePreferences.getKsSignaturePreferences().setKs(ks);

		try {
			log.info("Cargando fichero de caches " + ksCache);
			pdfSignaturePreferences.setKsCache(KeystoreUtil.loadKeystorePreferences(ksCache, ksCachePass));
		} catch (Exception e) {
			log.error("", e);
		}

		//TODO:¿Dónde se pone esta línea?
		pdfSignaturePreferences.getKsSignaturePreferences().setPasswordProtection(passwordProtection);

		
		String alias = PreferencesUtil.getString(PreferencesUtil.CERTIFICATE_ALIAS);
		if((alias == null || alias.length() <= 0) && ks != null && ks.aliases() != null &&  ks.aliases().hasMoreElements())
		{
			alias = ks.aliases().nextElement();
		}
		pdfSignaturePreferences.getKsSignaturePreferences().setAlias(alias);

		Boolean appearanceVisible = PreferencesUtil.getBoolean(PreferencesUtil.PDF_VISIBLE);
		String appearanceReason = PreferencesUtil.getString(PreferencesUtil.PDF_REASON);
		String appearanceLocation = PreferencesUtil.getString(PreferencesUtil.PDF_LOCATION);

		pdfSignaturePreferences.setVisible(appearanceVisible);
		pdfSignaturePreferences.setReason(appearanceReason);
		pdfSignaturePreferences.setLocation(appearanceLocation);

		pdfSignaturePreferences.setStartX(PreferencesUtil.getInteger(PreferencesUtil.PDF_STAMP_X));
		pdfSignaturePreferences.setStartY(PreferencesUtil.getInteger(PreferencesUtil.PDF_STAMP_Y));
		pdfSignaturePreferences.setWidht(PreferencesUtil.getInteger(PreferencesUtil.PDF_STAMP_WIDTH));
		pdfSignaturePreferences.setHeight(PreferencesUtil.getInteger(PreferencesUtil.PDF_STAMP_HEIGHT));

		Image sello = null;
		if (PreferencesUtil.getBoolean(PreferencesUtil.PDF_STAMP_ENABLE)) {
			try {
				sello = Image.getInstance(PreferencesUtil.getString(PreferencesUtil.PDF_STAMP_PATH));
			} catch (BadElementException e) {
				log.error("", e);
			} catch (MalformedURLException e) {
				log.error("", e);
			} catch (IOException e) {
				log.error("", e);
			}
		}
		pdfSignaturePreferences.setImage(sello);
		pdfSignaturePreferences.setCertified(PreferencesUtil.getInteger(PreferencesUtil.PDF_CERTIFIED));

		String tsurl = null;
		if (PreferencesUtil.getBoolean(PreferencesUtil.SIGN_TS_ENABLE)) {
			tsurl = PreferencesUtil.getString(PreferencesUtil.SIGN_TS_TSA);
		}

		pdfSignaturePreferences.setTimestampUrl(tsurl);
		pdfSignaturePreferences.setTimestampUser(null);
		pdfSignaturePreferences.setTimestampPassword(null);

		boolean addOCSP = PreferencesUtil.getBoolean(PreferencesUtil.SIGN_OCSP_ENABLE);
		pdfSignaturePreferences.setAddOCSP(addOCSP);

		return pdfSignaturePreferences;

	}

	public static void signPdf(PdfSignaturePreferences pdfSignaturePreferences) throws ConsolePreferencesException, IOException, PdfSignatureException,
			OCSPCoreException, RevokedException, ConnectionException, CertificateExpiredException, CertificateNotYetValidException,
			OCSPIssuerRequiredException, OCSPUnknownUrlException {
		
		InputStream is;
		OutputStream os;
		try {
			is = FileUtil.getInputStreamFromURI(PreferencesUtil.getString(PreferencesUtil.INPUT_PATH));
			os = FileUtil.getOutputStreamFromURI(PreferencesUtil.getString(PreferencesUtil.OUTPUT_PATH));
		} catch (Exception e) {
			throw new ConsolePreferencesException(e);
		}
		PdfService.sign(is,os, pdfSignaturePreferences, null);
		
	}

	public static XadesSignaturePreferences setXadesProperties(KeyStore ks) {
		
		XadesSignaturePreferences signaturePreferences = new XadesSignaturePreferences();
		signaturePreferences.setType(XadesSignaturePreferences.Type.Detached);
		signaturePreferences.getKsSignaturePreferences().setKs(ks);
		
		
		String alias = PreferencesUtil.getString(PreferencesUtil.CERTIFICATE_ALIAS);
		signaturePreferences.getKsSignaturePreferences().setAlias(alias);
		
		String ksCache = PreferencesUtil.getString(PreferencesUtil.KS_CACHE);
		String ksCachePass = PreferencesUtil.getString(PreferencesUtil.KS_CACHE_PASS);
		
		try {
			signaturePreferences.setKsCache(KeystoreUtil.loadKeystorePreferences(ksCache, ksCachePass));
		} catch (Exception e) {
			log.error("", e);
		}

		signaturePreferences.getKsSignaturePreferences().setPasswordProtection(passwordProtection);
		
		String tsurl = null;
		if (PreferencesUtil.getBoolean(PreferencesUtil.SIGN_TS_ENABLE)) {
			tsurl = PreferencesUtil.getString(PreferencesUtil.SIGN_TS_TSA);
		}	
		
		signaturePreferences.setTimestampUrl(tsurl);
		signaturePreferences.setTimestampUser(null);
		signaturePreferences.setTimestampPassword(null);
		
		boolean addOCSP = PreferencesUtil.getBoolean(PreferencesUtil.SIGN_OCSP_ENABLE);
		signaturePreferences.setAddOCSP(addOCSP);
	
		return signaturePreferences;
	}

	public static void signXades(XadesSignaturePreferences xadesPreferences) throws ConsolePreferencesException, XadesSignatureException, OCSPUnknownUrlException,
			IOException, CertificateExpiredException, CertificateNotYetValidException, RevokedException, OCSPCoreException,
			ConnectionException, OCSPIssuerRequiredException {

		/*
		 * unsupported
		 * validamos que siendo firma XML, el archivo origen y destino no sea el mismo
		 * // TODO esto se podría hacer con una firma enveloped/ing
		 * @see SignController (core; desde consola no se pueden hacer firmas sar) + SignController (desktop)
		 */
		log.debug("Input path: " + PreferencesUtil.getString(PreferencesUtil.INPUT_PATH));
		log.debug("Output path: " + PreferencesUtil.getString(PreferencesUtil.OUTPUT_PATH));
		if (PreferencesUtil.getString(PreferencesUtil.INPUT_PATH).equals(PreferencesUtil.getString(PreferencesUtil.OUTPUT_PATH))){
			String msg = "Se está intentando firmar un fichero XML sobre si mismo. Modifique el nombre del fichero de salida";
			log.error(msg);
			throw new XadesSignatureException(msg);
		}
		
		
		byte[] bytes = XadesService.signDetached(PreferencesUtil.getString(PreferencesUtil.INPUT_PATH), xadesPreferences);
		
		File output = new File(PreferencesUtil.getString(PreferencesUtil.OUTPUT_PATH));
		try{
			FileUtil.bytesToFile(bytes, output.getPath());
		}catch(IOException e){
			throw new ConsolePreferencesException(e);
		}
	}
	
	
	public static void main(String[] args) throws URISyntaxException {
		
		String test = "sinadura://sinadura.net:8999/subfolder/casa.pdf";
		
		System.out.println(test.substring(0, test.lastIndexOf("/")));
		System.out.println(test.substring(test.lastIndexOf("/")+1, test.length()));
				
				
				
		URI i = new URI("sinadura://sinadura.net:8999/casa.pdf");
		System.out.println(i.getHost());
		System.out.println(i.getPort());
		System.out.println(i.getUserInfo());
		System.out.println(i.getPath());
		System.out.println(i.getScheme());
		System.out.println(i.getSchemeSpecificPart());
		
		System.out.print("////////////////////");
		
		i = new URI("/casa.pdf");
		System.out.println(i.getHost());
		System.out.println(i.getPort());
		System.out.println(i.getUserInfo());
		System.out.println(i.getPath());
		System.out.println(i.getScheme());
		System.out.println(i.getSchemeSpecificPart());
		
		
		
		
	}
	
	
}
