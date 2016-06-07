package net.esle.sinadura.core.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.firmaJava.libreria.xades.XadesConfigUtil;

public class PropertiesCoreUtil {

	private static Log log = LogFactory.getLog(PropertiesCoreUtil.class);

	private static final String PATH_CONFIGURATION = "net/esle/sinadura/core/resources/configuration.properties";
	
	public static final String KEY_CORE_VERSION = "core.version";
	public static final String PDF_SIGN_RESERVED_SPACE = "pdf.sign.reserved.space";

	private static Properties configuration = null;

	private static Properties getProperties() {

		if (configuration == null) {
			configuration = new Properties();
			
			InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(PATH_CONFIGURATION);
			try {
				configuration.load(is);
			} catch (IOException e) {
				log.error("", e);
			}
		}
		return configuration;
	}
	
	public static String getProperty(String key) {
		
		return getProperties().getProperty(key);
	}

	/**
	 * Esta propiedad verifica si los nodos tienen el nombre y namespace esperado. Está por configuracion estatica, ya que no se
	 * puede propagar este parametro a traves de las funciones. Lo ideal sería que se indicará como parametro de entrada en la
	 * funcion de validacion (no de forma estatica), y borrar este metodo.
	 */
	public static void setCheckNodeName(boolean isCheckNodeName) {

		XadesConfigUtil.setCheckNodeName(isCheckNodeName);
	}
}

