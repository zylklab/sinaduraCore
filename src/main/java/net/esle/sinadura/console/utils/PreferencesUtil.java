package net.esle.sinadura.console.utils;

import java.io.FileInputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import net.esle.sinadura.console.exceptions.ConsolePreferencesException;

public class PreferencesUtil {

	private static Properties p = null;
	private static Map<String, String> map = new HashMap<String, String>();

	public static String INPUT_PATH = "input.path";
	public static String OUTPUT_PATH = "output.path";
	public static String PREFERENCES_PATH = "preferences.path";
	public static String ACTION = "action";
	public static String TYPE = "type";

	public static String ACTION_SIGN = "0";
	public static String ACTION_VALIDATE = "1";
	public static String TYPE_PDF = "0";
	public static String TYPE_XADES = "1";

	// Proxy
	public static final String PROXY_USER = "proxy.http.user";
	public static final String PROXY_PASS = "proxy.http.pass";
	public static final String PROXY_SYSTEM = "proxy.http.system";

	// PREFERENCES KEYS
	// Certifications
	public static final String CERT_TYPE = "preferencias.radioCertType.active";
	public static final String CERT_TYPE_VALUE_SOFTWARE = "0";
	public static final String CERT_TYPE_VALUE_HARDWARE = "1";
	public static final String CERT_TYPE_VALUE_MSCAPI = "2";

	public static final String HARDWARE_DISPOSITIVE = "hardware.dispositive";
	public static final String SOFTWARE_DISPOSITIVE = "software.dispositive";

	// Sign
	public static final String SIGN_TS_ENABLE = "sign.ts.enable";
	public static final String SIGN_TS_TSA = "sign.ts.tsa";
	public static final String SIGN_OCSP_ENABLE = "sign.ocsp.enable";

	public static final String KS_CACHE = "ks.cache";
	public static final String KS_CACHE_PASS = "ks.cache.pass";
	public static final String KS_TRUSTED = "ks.trusted";
	public static final String KS_TRUSTED_PASS = "ks.trusted.pass";
	public static final String CERTIFICATE_ALIAS = "certificate.alias";

	// Password callbackhander
	public static final String PASSWORD_CALLBACK_HANDLER = "callback.handler";

	// Appearance
	public static final String PDF_VISIBLE = "pdf.visible";
	public static final String PDF_PAGE = "pdf.page";
	public static final String PDF_REASON = "pdf.reason";
	public static final String PDF_LOCATION = "pdf.location";

	public static final String PDF_STAMP_ENABLE = "pdf.stamp.enable";
	public static final String PDF_STAMP_WIDTH = "pdf.stamp.width";
	public static final String PDF_STAMP_HEIGHT = "pdf.stamp.height";
	public static final String PDF_STAMP_X = "pdf.stamp.x";
	public static final String PDF_STAMP_Y = "pdf.stamp.y";
	public static final String PDF_STAMP_PATH = "pdf.stamp.path";

	/*
	 * NOT_CERTIFIED (0)
	 * CERTIFIED_NO_CHANGES_ALLOWED (1)
	 * CERTIFIED_FORM_FILLING (2)
	 * CERTIFIED_FORM_FILLING_AND_ANNOTATIONS (3)
	 */
	public static final String PDF_CERTIFIED = "pdf.certified";

	
	// Validate
	// public static final String VALIDATE_TS_ENABLE = "validate.ts.enable";
	// public static final String VALIDATE_TS_TSA = "validate.ts.tsa";
	// public static final String VALIDATE_OCSP_ENABLE = "validate.ocsp.enable";
	// public static final String VALIDATE_CERTIFIED = "validate.certified";

	public static void parseArgs(String[] args) throws ConsolePreferencesException {

		try{
			
			map = new HashMap<String, String>();
			
			for (int i = 0; i < args.length; i++) {

				if (args[i].equals("--input")) {
					map.put(INPUT_PATH, args[i + 1]);
				}
				if (args[i].equals("--output")) {
					map.put(OUTPUT_PATH, args[i + 1]);
				}
				if (args[i].equals("--preferences")) {
					map.put(PREFERENCES_PATH, args[i + 1]);
					p = new Properties();
					p.load(new FileInputStream(args[i + 1]));
				}
				if (args[i].equals("--sign")) {
					map.put(ACTION, ACTION_SIGN);
				}
				if (args[i].equals("--validate")) {
					map.put(ACTION, ACTION_VALIDATE);
				}
				if (args[i].equals("--xades")) {
					map.put(TYPE, TYPE_XADES);
				}
				if (args[i].equals("--pdf")) {
					map.put(TYPE, TYPE_PDF);
				}
			}
			
		}catch(Exception e){
			throw new ConsolePreferencesException(e);
		}
	}
	
	private static String getProperty(String key) {
		
		String value = map.get(key);
		
		if (value == null) {
			value = p.getProperty(key);
		} 
		
		return value;
	}
	
	public static int getInteger(String key) {

		return Integer.parseInt(getProperty(key));
	}

	public static String getString(String key) {

		return getProperty(key);
	}

	public static boolean getBoolean(String key) {

		return Boolean.parseBoolean(getProperty(key));
	}
}
