/*
 * # Copyright 2008 zylk.net # # This file is part of Sinadura. # # Sinadura is free software: you can redistribute it
 * and/or modify # it under the terms of the GNU General Public License as published by # the Free Software Foundation,
 * either version 2 of the License, or # (at your option) any later version. # # Sinadura is distributed in the hope
 * that it will be useful, # but WITHOUT ANY WARRANTY; without even the implied warranty of # MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the # GNU General Public License for more details. # # You should have received a copy
 * of the GNU General Public License # along with Sinadura. If not, see <http://www.gnu.org/licenses/>. [^] # # See
 * COPYRIGHT.txt for copyright notices and details. #
 */
package net.esle.sinadura.core.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;


public class KeystoreUtil {

	public static KeyStore copyKeystore(KeyStore keyStore) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException {

		ByteArrayOutputStream os = new ByteArrayOutputStream();
		char[] password = { 's', 'i', 'n', 'a', 'd', 'u', 'r', 'a' };
		keyStore.store(os, password);

		InputStream is = new ByteArrayInputStream(os.toByteArray());

		KeyStore ksTemp = KeyStore.getInstance(keyStore.getType());
		ksTemp.load(is, password);

		return ksTemp;
	}

	
	public static KeyStore loadKeystorePreferences(String path, String pass) throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException {

		FileInputStream fis = new FileInputStream(path);
		return loadKeystorePreferences(fis, pass);
	}

	public static KeyStore loadKeystorePreferences(InputStream is, String pass) throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException {

		char[] password = new char[pass.length()];
		for (int i = 0; i < pass.length(); i++) {
			password[i] = pass.charAt(i);
		}

		KeyStore ks = null;

		ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(is, password);

		return ks;

	}

}





