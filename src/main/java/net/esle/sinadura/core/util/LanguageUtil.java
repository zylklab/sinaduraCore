/*
 * # Copyright 2008 zylk.net 
 * # 
 * # This file is part of Sinadura. 
 * # 
 * # Sinadura is free software: you can redistribute it and/or modify 
 * # it under the terms of the GNU General Public License as published by 
 * # the Free Software Foundation, either version 2 of the License, or 
 * # (at your option) any later version. 
 * # 
 * # Sinadura is distributed in the hope that it will be useful, 
 * # but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * # GNU General Public License for more details. 
 * # 
 * # You should have received a copy of the GNU General Public License 
 * # along with Sinadura. If not, see <http://www.gnu.org/licenses/>. [^] 
 * # 
 * # See COPYRIGHT.txt for copyright notices and details. 
 * #
 */
package net.esle.sinadura.core.util;


import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.ResourceBundle;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class LanguageUtil {
	
	private static Log log = LogFactory.getLog(LanguageUtil.class);
	
	private static final String LANGUAGE_FILE_PATH = "net/esle/sinadura/core/resources/i18n/language";
	
	private static ResourceBundle language;
	private static Locale locale;
	
	static {
		locale = new Locale("es","ES");
		reloadLanguage();
	}
	
	public static Locale getLocale() {

		return locale;
	}
	
	public static void reloadLocale(Locale loc) {
		
		locale = loc;
		reloadLanguage();
	}
	
	public static ResourceBundle getLanguage() {

		return language;
	}
	
	private static void reloadLanguage() {
		
		language = ResourceBundle.getBundle(LANGUAGE_FILE_PATH, locale);
	}

	public static SimpleDateFormat getShortFormater() {

		if (Locale.getDefault().getCountry().equals("ES") && Locale.getDefault().getLanguage().equals("es")) {
			return (new SimpleDateFormat("dd-MM-yyyy"));
			
		} else if (Locale.getDefault().getCountry().equals("ES") && Locale.getDefault().getLanguage().equals("eu")) {
			return (new SimpleDateFormat("yyyy-MM-dd"));
			
		} else {
			return (new SimpleDateFormat("MM-dd-yyyy"));
		}
	}
	
	public static SimpleDateFormat getFullFormater() {

		if (Locale.getDefault().getCountry().equals("ES") && Locale.getDefault().getLanguage().equals("es")) {
			return (new SimpleDateFormat("HH:mm:ss dd-MM-yyyy"));
			
		} else if (Locale.getDefault().getCountry().equals("ES") && Locale.getDefault().getLanguage().equals("eu")) {
			return (new SimpleDateFormat("HH:mm:ss yyyy-MM-dd"));
			
		} else {
			return (new SimpleDateFormat("HH:mm:ss MM-dd-yyyy"));
		}
	}
	
	public static SimpleDateFormat getTimeFormater() {

		if (Locale.getDefault().getCountry().equals("ES") && Locale.getDefault().getLanguage().equals("es")) {
			return (new SimpleDateFormat("HH:mm:ss"));
			
		} else if (Locale.getDefault().getCountry().equals("ES") && Locale.getDefault().getLanguage().equals("eu")) {
			return (new SimpleDateFormat("HH:mm:ss"));
			
		} else {
			return (new SimpleDateFormat("HH:mm:ss"));
		}
	}
	
	
}
