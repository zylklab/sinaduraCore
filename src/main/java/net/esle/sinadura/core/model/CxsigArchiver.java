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
package net.esle.sinadura.core.model;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import net.esle.sinadura.core.exceptions.ArchiverException;
import net.esle.sinadura.core.exceptions.UknownArchiverException;
import net.esle.sinadura.core.util.FileUtil;

/**
 * Representa a los empaquetados cxsig
 *
 */
public class CxsigArchiver {

	private String tmpPath;
	private static final String SIGNATURE_FILE_NAME = "signature.xsig";
	
	
	public CxsigArchiver(InputStream file) throws UknownArchiverException {
		
		try {
			// TODO validar que es un fichero cxsig correcto
			createTmpDir();
			FileUtil.unzipIntoDirectory(file, tmpPath);

		} catch (IOException e) {
			throw new UknownArchiverException(e);
		} catch (URISyntaxException e) {
			throw new UknownArchiverException(e); 
		}
	}

	public String getSignature() throws ArchiverException {

		File signature = new File(tmpPath + File.separatorChar + SIGNATURE_FILE_NAME);
		if (signature.exists()) {
			return signature.getAbsolutePath();
		} else {
			throw new ArchiverException("No se ha encontrado el fichero de firma");	
		}
	}

	public List<String> getDocuments() throws ArchiverException {
		
		List<String> listaValues = new ArrayList<String>();
	
		File tmpDir = new File(tmpPath);
		File[] files = tmpDir.listFiles();
		for (File file : files) {
			// todo lo que no sea la firma
			if (!file.getName().equals(SIGNATURE_FILE_NAME)) {
				listaValues.add(file.getAbsolutePath());
			}
		}
		return listaValues;
	}
	

	/**
	 * Limpia el tmp dir. Llamar a este metodo al terminar.
	 * 
	 */
	public void close() {

		FileUtil.deleteDir(tmpPath);
	}

	private void createTmpDir() {

		// crear tmp
		File tmp_base = new File(System.getProperty("java.io.tmpdir"));
		this.tmpPath = tmp_base.getAbsolutePath() + File.separatorChar + System.currentTimeMillis();
		File tmpFile = new File(this.tmpPath);
		tmpFile.mkdir();
	}

}
