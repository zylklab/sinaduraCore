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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import net.esle.sinadura.core.exceptions.ArchiverException;
import net.esle.sinadura.core.exceptions.UknownArchiverException;
import net.esle.sinadura.core.util.FileUtil;
import net.esle.sinadura.core.util.PropertiesCoreUtil;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Empaquetado para las firmas xades detached (SAR).
 * 
 * @author alfredo
 * 
 */
public class Archiver {

	private static final String VERSION = PropertiesCoreUtil.getProperty(PropertiesCoreUtil.KEY_CORE_VERSION);
	private static final String PROVIDER = "Sinadura";
	
	private static final String METAINF = "META-INF";
	private static final String MANIFEST = "manifest.xml";

	private static final String TAG_DOCUMENT = "document";
	private static final String TAG_SIGNATURE = "signature";
	private static final String GROUP_DOCUMENT = "documents";
	private static final String GROUP_SIGNATURE = "signatures";

	private String tmpPath;
	private boolean hasManifest; // para la gestion de los SAR generados externamente

	public Archiver() throws ArchiverException {
	
		try {
			createTmpDir();
			createManifest();
			hasManifest = true;
			
		} catch (IOException e) {
			throw new ArchiverException(e);
		}
	}

	public Archiver(String filePath) throws UknownArchiverException {
		
		try {
			// TODO gestion de URI??
			
			// Esto del mimetype habria que quitarlo para que el parametro de entrada sea un inputstream. Y delegar lo del
			// mimetype en el Desktop. Habria que refactorizar antes el metodo de firmaXades, ya que tal y como esta implementado
			// ahora le entran ficheros sin extension sar y se encarga el de hacer una logica u otra.
			String mimeType = FileUtil.getMimeType(filePath);
			if (mimeType == null || !mimeType.equals(FileUtil.MIMETYPE_SAR) ) {
				throw new UknownArchiverException("no contiene extesion sar");
			}
			createTmpDir();
			FileUtil.unzipIntoDirectory(filePath, tmpPath);
			hasManifest = hasArchiverManifest();
			validateArchiver();

		} catch (IOException e) {
			throw new UknownArchiverException(e);
		} catch (URISyntaxException e) {
			throw new UknownArchiverException(e); 
		}
	}

	public void addDocument(String filePath) throws ArchiverException {
		
		try {
			String documentPath = tmpPath + File.separatorChar + new File(filePath).getName();
			documentPath = FileUtil.normalizarBarras(documentPath);
			FileUtil.copyFile(filePath, documentPath);
			if (hasManifest) {
				writeProperty(documentPath, Archiver.TAG_DOCUMENT, Archiver.GROUP_DOCUMENT);
			}
		} catch (IOException e) {
			throw new ArchiverException(e);
		}
	}

	public void addDocument(byte[] bytes, String name) throws ArchiverException {

		try {
			String documentPath = tmpPath + File.separatorChar + name;
			FileUtil.bytesToFile(bytes, documentPath);
			if (hasManifest) {
				writeProperty(documentPath, Archiver.TAG_DOCUMENT, Archiver.GROUP_DOCUMENT);
			}
		} catch (IOException e) {
			throw new ArchiverException(e);
		}
	}

	public void addSignature(byte[] bytes) throws ArchiverException {
		
		try {
			String name = System.currentTimeMillis() + "." + FileUtil.EXTENSION_XML;
			String signaturePath = tmpPath + File.separatorChar + name;
			FileUtil.bytesToFile(bytes, signaturePath);
			if (hasManifest) {
				writeProperty(signaturePath, Archiver.TAG_SIGNATURE, Archiver.GROUP_SIGNATURE);
			}
		} catch (IOException e) {
			throw new ArchiverException(e);
		}
	}

	private void writeProperty(String path, String tag, String group) throws IOException {
		
		if (new File(tmpPath + File.separatorChar + Archiver.METAINF + File.separatorChar + Archiver.MANIFEST).exists()) {

			BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(new File(tmpPath + File.separatorChar + Archiver.METAINF
					+ File.separatorChar + Archiver.MANIFEST)), "UTF-8"));
			String linea;
			String aux = "";
			while ((linea = br.readLine()) != null) {
				if (linea.equals("</" + group + ">")) {
					aux += "<" + tag + ">\n";
					aux += "<path>" + FileUtil.getLocalFileFromURI(path).getName() + "</path>\n";
					aux += "</" + tag + ">\n";
				}
				aux += linea + "\n";
			}
			

			BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(new File(tmpPath + File.separatorChar + Archiver.METAINF
					+ File.separatorChar + Archiver.MANIFEST)), "UTF-8" ));
			
			bw.write(aux);
			bw.flush();
			bw.close();
		}
	}

	public String getDocument() throws ArchiverException {
		// Este metodo sobra.

		return getDocuments()[0];
	}

	public String[] getDocuments() throws ArchiverException {
		
		List<String> listaValues;
		try {
			if (hasManifest) {
				listaValues = getXPathValues(tmpPath + File.separatorChar + Archiver.METAINF + File.separatorChar + Archiver.MANIFEST,
						Archiver.TAG_DOCUMENT);
			} else {
				listaValues = getDocumentsWithoutManifest();
			}
			
			String[] array = (String[]) listaValues.toArray(new String[listaValues.size()]);
			return array;
			
		} catch (XPathExpressionException e) {
			throw new ArchiverException(e);
		} catch (ParserConfigurationException e) {
			throw new ArchiverException(e);
		} catch (SAXException e) {
			throw new ArchiverException(e);
		} catch (IOException e) {
			throw new ArchiverException(e);
		}
	}
	
	public String[] getSignatures() throws ArchiverException {

		List<String> listaValues;
		try {
			if (hasManifest) {
				listaValues = getXPathValues(tmpPath + File.separatorChar + Archiver.METAINF + File.separatorChar + Archiver.MANIFEST,
					Archiver.TAG_SIGNATURE);
			} else {
				listaValues = getSignaturesWithoutManifest();
			}
			
			String[] array = (String[]) listaValues.toArray(new String[listaValues.size()]);
			return array;
			
		} catch (XPathExpressionException e) {
			throw new ArchiverException(e);
		} catch (ParserConfigurationException e) {
			throw new ArchiverException(e);
		} catch (SAXException e) {
			throw new ArchiverException(e);
		} catch (IOException e) {
			throw new ArchiverException(e);
		}
	}

	private List<String> getXPathValues(String xmlPath, String tag) throws ParserConfigurationException, SAXException, IOException,
			XPathExpressionException {

		List<String> listaValues = new ArrayList<String>();

		DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = domFactory.newDocumentBuilder();
		
		InputStream is = new FileInputStream(new File(xmlPath));
		Reader reader = new InputStreamReader(is, "UTF-8");
		
		InputSource source = new InputSource(reader);
		source.setEncoding("UTF-8");
		Document doc = builder.parse(source);

		XPathFactory factory = XPathFactory.newInstance();
		XPath xpath = factory.newXPath();
		XPathExpression expr = xpath.compile("//" + tag + "/path");

		Object result = expr.evaluate(doc, XPathConstants.NODESET);
		NodeList nodes = (NodeList) result;
		for (int i = 0; i < nodes.getLength(); i++) {
			listaValues.add(tmpPath + File.separatorChar + nodes.item(i).getTextContent());
		}
		return listaValues;
	}
	
	private List<String> getSignaturesWithoutManifest() {
	
		List<String> listaValues = new ArrayList<String>();
		
		File tmpDir = new File(tmpPath);
		File[] files = tmpDir.listFiles();
		for (File file : files) {
			if (file.getName().toUpperCase().endsWith(FileUtil.EXTENSION_XML.toUpperCase())) {
				listaValues.add(file.getAbsolutePath());
			}
		}
		
		return listaValues;
	}
	
	private List<String> getDocumentsWithoutManifest() {
		
		List<String> listaValues = new ArrayList<String>();
		
		File tmpDir = new File(tmpPath);
		File[] files = tmpDir.listFiles();
		for (File file : files) {
			// todo lo que no sea xml
			if (!file.getName().toUpperCase().endsWith(FileUtil.EXTENSION_XML.toUpperCase())) {
				listaValues.add(file.getAbsolutePath());
			}
		}
		
		return listaValues;
	}

	public byte[] generate() throws ArchiverException {
		
		try {
			return FileUtil.zipDir(tmpPath, false);
			
		} catch (IOException e) {
			throw new ArchiverException(e);
		}
		
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

	private void createManifest() throws IOException {

		File metaInf = new File(tmpPath + File.separatorChar + Archiver.METAINF);
		metaInf.mkdir();

		File manifest = new File(metaInf.getAbsolutePath() + File.separatorChar + Archiver.MANIFEST);
		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(manifest), "UTF-8" ));

		bw.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
		bw.write("<content>\n");
		bw.write("<provider>" + Archiver.PROVIDER + "</provider>\n");
		bw.write("<version>" + Archiver.VERSION + "</version>\n");
		bw.write("<" + Archiver.GROUP_DOCUMENT + ">\n");
		bw.write("</" + Archiver.GROUP_DOCUMENT + ">\n");
		bw.write("<" + Archiver.GROUP_SIGNATURE + ">\n");
		bw.write("</" + Archiver.GROUP_SIGNATURE + ">\n");
		bw.write("</content>\n");

		bw.flush();
		bw.close();
	}

	private boolean hasArchiverManifest() {

		try {
			if (new File(tmpPath + File.separatorChar + Archiver.METAINF + File.separatorChar + Archiver.MANIFEST).exists()) {
	
				BufferedReader br = new BufferedReader(new FileReader(new File(tmpPath + File.separatorChar + Archiver.METAINF
						+ File.separatorChar + Archiver.MANIFEST)));
	
				String linea;
				while ((linea = br.readLine()) != null) {
					if (linea.contains(Archiver.PROVIDER)) {
						return true;
					}
				}
			}
			
			return false;
			
		} catch (IOException e) {
			return false;	
		}
	}
	
	private void validateArchiver() throws UknownArchiverException {

		if (!hasManifest) {	
			// si no tiene ni documentos ni firmas -> SAR invalido (la comprobacion no es muy estricta...)
			List<String> docs = getDocumentsWithoutManifest();
			if (docs == null || docs.size() == 0) {
				throw new UknownArchiverException();
			}
			
			List<String> signs = getSignaturesWithoutManifest();
			if (signs == null || signs.size() == 0) {
				throw new UknownArchiverException();
			}
		}	
	}
	
}
