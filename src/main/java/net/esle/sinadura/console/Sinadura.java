package net.esle.sinadura.console;

import java.security.KeyStore;
import java.text.MessageFormat;

import net.esle.sinadura.console.controllers.SignController;
import net.esle.sinadura.console.controllers.ValidateController;
import net.esle.sinadura.console.exceptions.ConsolePreferencesException;
import net.esle.sinadura.console.utils.ExitCodeManagerUtils;
import net.esle.sinadura.console.utils.PreferencesUtil;
import net.esle.sinadura.core.model.PdfSignaturePreferences;
import net.esle.sinadura.core.model.XadesSignaturePreferences;
import net.esle.sinadura.core.util.LanguageUtil;
import net.esle.sinadura.ee.EEModulesManager;
import net.esle.sinadura.ee.exceptions.EEModuleGenericException;
import net.esle.sinadura.ee.exceptions.EEModuleNotFoundException;
import net.esle.sinadura.ee.interfaces.ProxyEEModule;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public class Sinadura {

	private static Log log = LogFactory.getLog(Sinadura.class.getName());

	
	public static void main(String[] args){

		try{
			
			// 0. Parseo de los argumentos
			PreferencesUtil.parseArgs(args);

			// Configuracion del proxy
			
			// ee
			if (PreferencesUtil.getBoolean(PreferencesUtil.PROXY_SYSTEM)) {
				try{
					
					ProxyEEModule proxyUtil = EEModulesManager.getProxyModule();
					
					proxyUtil.configureProxy(PreferencesUtil.getString(PreferencesUtil.PROXY_USER),
											PreferencesUtil.getString(PreferencesUtil.PROXY_PASS));
				}catch(EEModuleNotFoundException e){
					throw new ConsolePreferencesException(MessageFormat.format(LanguageUtil.getLanguage().getString("ee.proxy.disabled"), "proxy"));
				}catch(EEModuleGenericException e){
					log.error(e);
				}
			}
			

			//----------------------
			// 1. firma
			//----------------------
			KeyStore ks = null;
			if (PreferencesUtil.getString(PreferencesUtil.ACTION) != null && PreferencesUtil.getString(PreferencesUtil.ACTION).equals(PreferencesUtil.ACTION_SIGN)) {

				ks = SignController.loadKeyStore();
				
				// -- pdf
				//--------------
				if (PreferencesUtil.getString(PreferencesUtil.TYPE) != null && PreferencesUtil.getString(PreferencesUtil.TYPE).equals(PreferencesUtil.TYPE_PDF)) {
					PdfSignaturePreferences pdfPreferences = SignController.setPdfProperties(ks);
					SignController.signPdf(pdfPreferences);
					
				// -- xades
				//--------------
				} else if (PreferencesUtil.getString(PreferencesUtil.TYPE) != null && PreferencesUtil.getString(PreferencesUtil.TYPE).equals(PreferencesUtil.TYPE_XADES)) {
					XadesSignaturePreferences xadesPreferences = SignController.setXadesProperties(ks);
					SignController.signXades(xadesPreferences);
					
				} else {
					log.error("INDIQUE UN TIPO DE FIRMA VÁLIDA. --pdf o --xades");
				}
				
				
			//----------------------
			// 2. validación
			//----------------------
			} else if (PreferencesUtil.getString(PreferencesUtil.ACTION) != null && PreferencesUtil.getString(PreferencesUtil.ACTION).equals(PreferencesUtil.ACTION_VALIDATE)) {
				
				// -- pdf
				//--------------
				if (PreferencesUtil.getString(PreferencesUtil.TYPE) != null && PreferencesUtil.getString(PreferencesUtil.TYPE).equals(PreferencesUtil.TYPE_PDF)) {
					ValidateController.validatePDF();
					
				// -- xades
				//--------------
				} else if (PreferencesUtil.getString(PreferencesUtil.TYPE) != null && PreferencesUtil.getString(PreferencesUtil.TYPE).equals(PreferencesUtil.TYPE_XADES)) {
					ValidateController.validateXades();
					
				} else {
					log.error("INDIQUE UN TIPO DE validación VÁLIDA. --pdf o --xades");
				}
			} else {
				log.error("INDIQUE LA ACCION QUE DESEA REALIZAR. --sign o --validate");
			}
			
			
		// @nota propagan las excepciones en el ExitCodeManagerUtils
		}catch(Exception e){
			System.exit(ExitCodeManagerUtils.getExitCode(e));
		}
	}
}
