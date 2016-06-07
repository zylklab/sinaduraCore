
package net.esle.sinadura.core.xades.validator;

import java.io.InputStream;
import java.util.List;

import net.esle.sinadura.core.exceptions.XadesValidationFatalException;
import net.esle.sinadura.core.model.ValidationPreferences;
import net.esle.sinadura.core.model.XadesSignatureInfo;



public interface XadesValidator {
	
	public List<XadesSignatureInfo> validarFichero(InputStream signature, InputStream document, String baseUri,
			ValidationPreferences validationPreferences) throws XadesValidationFatalException;

}

