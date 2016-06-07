
package net.esle.sinadura.core.xades.validator.impl;

import java.io.InputStream;
import java.util.List;

import net.esle.sinadura.core.exceptions.XadesValidationFatalException;
import net.esle.sinadura.core.model.ValidationPreferences;
import net.esle.sinadura.core.model.XadesSignatureInfo;
import net.esle.sinadura.core.xades.CompleteValidation;
import net.esle.sinadura.core.xades.validator.XadesValidator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public class SinaduraXadesValidator implements XadesValidator {

	private static Log log = LogFactory.getLog(SinaduraXadesValidator.class);

	@Override
	public List<XadesSignatureInfo> validarFichero(InputStream signature, InputStream document, String baseUri,
			ValidationPreferences validationPreferences) throws XadesValidationFatalException {

		log.info("SinaduraXadesValidator start");

		return CompleteValidation.validarFichero(signature, baseUri, validationPreferences);
	}
	
}

