package net.esle.sinadura.console.controllers;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

import net.esle.sinadura.console.exceptions.ConsolePreferencesException;
import net.esle.sinadura.console.exceptions.ValidationResultInvalidException;
import net.esle.sinadura.console.utils.PreferencesUtil;
import net.esle.sinadura.core.exceptions.ValidationFatalException;
import net.esle.sinadura.core.exceptions.XadesValidationFatalException;
import net.esle.sinadura.core.interpreter.SignatureInfo;
import net.esle.sinadura.core.interpreter.ValidationInterpreterUtil;
import net.esle.sinadura.core.model.PDFSignatureInfo;
import net.esle.sinadura.core.model.Status;
import net.esle.sinadura.core.model.ValidationPreferences;
import net.esle.sinadura.core.model.XadesSignatureInfo;
import net.esle.sinadura.core.service.PdfService;
import net.esle.sinadura.core.service.XadesService;
import net.esle.sinadura.core.util.KeystoreUtil;
import net.esle.sinadura.core.xades.validator.XadesValidator;
import net.esle.sinadura.core.xades.validator.XadesValidatorFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class ValidateController {

	private static Log logger = LogFactory.getLog(ValidateController.class.getName());

	public static void validatePDF() throws ConsolePreferencesException, ValidationFatalException {

		List<PDFSignatureInfo> pdfSignatureInfos = null;
			try {
				pdfSignatureInfos = PdfService.validate(
									PreferencesUtil.getString(PreferencesUtil.INPUT_PATH),
									KeystoreUtil.loadKeystorePreferences(PreferencesUtil.getString(PreferencesUtil.KS_CACHE), PreferencesUtil.getString(PreferencesUtil.KS_CACHE_PASS)), 
									KeystoreUtil.loadKeystorePreferences(PreferencesUtil.getString(PreferencesUtil.KS_TRUSTED), PreferencesUtil.getString(PreferencesUtil.KS_TRUSTED_PASS))
								);
				
			// TODO esto podría ir dentro de KeystoreUtil.loadKeystorePreferences, pero de momento lo dejo así
			} catch (KeyStoreException e) {
				throw new ConsolePreferencesException(e);
			} catch (NoSuchAlgorithmException e) {
				throw new ConsolePreferencesException(e);
			} catch (CertificateException e) {
				throw new ConsolePreferencesException(e);
			} catch (IOException e) {
				throw new ConsolePreferencesException(e);
				
			// TODO eso también habría que limpiarlo por dentro, para saber porque da ese ValidationFatalException
			}catch( ValidationFatalException e){
				// si es derivado del fichero de entrada, es error de consola
				if (e.getCause() instanceof IOException |
						e.getCause() instanceof URISyntaxException){
					throw new ConsolePreferencesException(e); 
				}else{
					throw e;
				}
			}
		
			
		if (pdfSignatureInfos != null) {
			for (PDFSignatureInfo pdf : pdfSignatureInfos) {

				String m = pdf.toString();
				logger.info(m);

				if (!(pdf.getStatus().equals(Status.VALID) || pdf.getStatus().equals(Status.VALID_WARNING))) {
					// terminar el programa de forma erronea
					throw new ValidationFatalException("la firma no es completamente valida");
				}
			}
		}
	}

	public static void validateXades() throws ConsolePreferencesException, CertificateException, XadesValidationFatalException, ValidationResultInvalidException {

		List<XadesSignatureInfo> xadesSignatureInfos = null;
		try{
			
			// TODO parametrizar el tipo de validador
			XadesValidator xadesValidator;
			
			// ver desktop
			if (false) {
//				xadesValidator = XadesValidatorFactory.getZainInstance(endPoint, truststorePath, truststorePassword,
//						keystorePath, keystorePassword, requestLogSavePath, responseLogSavePath);
			} else {
				xadesValidator = XadesValidatorFactory.getSinaduraInstance();
			}
			
			ValidationPreferences validationPreferences = new ValidationPreferences();
			validationPreferences.setCheckRevocation(true);
			validationPreferences.setKsCache(KeystoreUtil.loadKeystorePreferences(PreferencesUtil.getString(PreferencesUtil.KS_CACHE),
					PreferencesUtil.getString(PreferencesUtil.KS_CACHE_PASS)));
			validationPreferences.setKsTrust(KeystoreUtil.loadKeystorePreferences(PreferencesUtil.getString(PreferencesUtil.KS_TRUSTED),
					PreferencesUtil.getString(PreferencesUtil.KS_TRUSTED_PASS)));
			
			// TODO el document lo paso a null, porque se que el validador de Sinadura no lo utiliza. Pero habria que pasarselo. 
			xadesSignatureInfos = XadesService.validateXml(xadesValidator, PreferencesUtil.getString(PreferencesUtil.INPUT_PATH),
					null, validationPreferences);
		
		// TODO esto podría ir dentro de KeystoreUtil.loadKeystorePreferences, pero de momento lo dejo así
		} catch (KeyStoreException e) {
			throw new ConsolePreferencesException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new ConsolePreferencesException(e);
		} catch (CertificateException e) {
			throw new ConsolePreferencesException(e);
		} catch (IOException e) {
			throw new ConsolePreferencesException(e);
			
		// TODO eso también habría que limpiarlo por dentro, para saber porque da ese ValidationFatalException
		}catch( XadesValidationFatalException e){
			// si es derivado del fichero de entrada, es error de consola
			if (e.getCause() instanceof IOException |
					e.getCause() instanceof URISyntaxException){
				throw new ConsolePreferencesException(e); 
			}else{
				throw e;
			}
		}
		
		if (xadesSignatureInfos != null) {
			for (SignatureInfo xades : ValidationInterpreterUtil.parseResultadoValidacion(xadesSignatureInfos)) {
				if (!(xades.getStatus().equals(Status.VALID) || xades.getStatus().equals(Status.VALID_WARNING))) {
					// terminar el programa de forma erronea
					throw new ValidationResultInvalidException("la firma no es completamente valida");
				}
			}
		}
	}

	public static void validateP7() {

		// TODO
	}
}
