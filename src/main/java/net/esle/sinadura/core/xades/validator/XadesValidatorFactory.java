
package net.esle.sinadura.core.xades.validator;

import net.esle.sinadura.core.exceptions.XadesValidationFatalException;
import net.esle.sinadura.core.xades.validator.impl.SinaduraXadesValidator;
import net.esle.sinadura.core.xades.validator.impl.ZainXadesValidator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public class XadesValidatorFactory {

	private static Log log = LogFactory.getLog(XadesValidatorFactory.class);

	
	public static XadesValidator getZainInstance(String endPoint, String truststorePath, String truststorePassword,
			String keystorePath, String keystorePassword, String proxyUser, String proxyPass, boolean logActive,
			String requestLogSavePath, String responseLogSavePath, String language) throws XadesValidationFatalException {
		
		log.info("getZainInstance");
		
		ZainXadesValidator zainXadesValidator = new ZainXadesValidator();
		zainXadesValidator.configure(endPoint, truststorePath, truststorePassword, keystorePath, keystorePassword, proxyUser,
				proxyPass, logActive, requestLogSavePath, responseLogSavePath, language);
		
		return zainXadesValidator;
	}
	
	public static XadesValidator getSinaduraInstance() {
		
		log.info("getSinaduraInstance");
		
		return new SinaduraXadesValidator();
	}
	
}

