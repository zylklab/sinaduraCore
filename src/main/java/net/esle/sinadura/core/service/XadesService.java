package net.esle.sinadura.core.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.esle.sinadura.core.exceptions.ArchiverException;
import net.esle.sinadura.core.exceptions.ConnectionException;
import net.esle.sinadura.core.exceptions.DigidocException;
import net.esle.sinadura.core.exceptions.OCSPCoreException;
import net.esle.sinadura.core.exceptions.OCSPIssuerRequiredException;
import net.esle.sinadura.core.exceptions.OCSPUnknownUrlException;
import net.esle.sinadura.core.exceptions.RevokedException;
import net.esle.sinadura.core.exceptions.UknownArchiverException;
import net.esle.sinadura.core.exceptions.XadesSignatureException;
import net.esle.sinadura.core.exceptions.XadesValidationFatalException;
import net.esle.sinadura.core.model.Archiver;
import net.esle.sinadura.core.model.CxsigArchiver;
import net.esle.sinadura.core.model.DataFile;
import net.esle.sinadura.core.model.ValidationPreferences;
import net.esle.sinadura.core.model.XadesSignatureInfo;
import net.esle.sinadura.core.model.XadesSignaturePreferences;
import net.esle.sinadura.core.util.FileUtil;
import net.esle.sinadura.core.util.LanguageUtil;
import net.esle.sinadura.core.validate.DigidocUtil;
import net.esle.sinadura.core.xades.XAdESBESDetachedSignature;
import net.esle.sinadura.core.xades.XAdESFacturaeSignature;
import net.esle.sinadura.core.xades.XAdESTDetachedSignature;
import net.esle.sinadura.core.xades.XAdESXLDetachedSignature;
import net.esle.sinadura.core.xades.validator.XadesValidator;

import org.apache.commons.io.IOUtils;
import org.apache.xml.security.utils.Base64;

import es.mityc.firmaJava.libreria.xades.ResultadoEnum;

public class XadesService {
	
	// TODO pasar entradas de paths a bytes?
	
	public static byte[] signFacturae(InputStream document, XadesSignaturePreferences signaturePreferences) throws XadesSignatureException,
			OCSPUnknownUrlException, CertificateExpiredException, CertificateNotYetValidException, RevokedException, OCSPCoreException,
			ConnectionException, OCSPIssuerRequiredException {

		XAdESFacturaeSignature signer = new XAdESFacturaeSignature(document, signaturePreferences);
		byte[] signature = signer.execute();
		
		return signature;	
	}
	
	
	// En las firmas detached creo que los recursos a firmar tienen que estar en filesystem, porque al crear el objeto reference del xml lo
	// que se añade es una uri a filesystem y al validar ese objeto reference si no encuentra el recurso peta el proceso de firma.
	// No se si de alguna manera podría haber algún tipo de resolver en memoria.
	
	/**
	 * Para firma de un archivo.
	 * 
	 * @param path
	 * @param signaturePreferences
	 * 
	 * @return xml
	 * @throws OCSPUnknownUrlException 
	 * @throws OCSPIssuerRequiredException 
	 * @throws ConnectionException 
	 * @throws OCSPCoreException 
	 * @throws RevokedException 
	 * @throws CertificateNotYetValidException 
	 * @throws CertificateExpiredException 
	 */
	public static byte[] signDetached(String path, XadesSignaturePreferences signaturePreferences) throws XadesSignatureException,
			OCSPUnknownUrlException, CertificateExpiredException, CertificateNotYetValidException, RevokedException, OCSPCoreException,
			ConnectionException, OCSPIssuerRequiredException {

		byte[] document = null;
		 
		if (signaturePreferences.getType().equals(XadesSignaturePreferences.Type.Detached)) {
			
			// unsupported
			if (!FileUtil.isXadesEnabled(path)){
				throw new XadesSignatureException(LanguageUtil.getLanguage().getString("error.xades.webdav"));
			}
			
			// firma
			if (signaturePreferences.getAddOCSP()) {
				XAdESXLDetachedSignature signature = new XAdESXLDetachedSignature(path, signaturePreferences);
				document = signature.execute();
				
			} else if (signaturePreferences.getTimestampUrl() != null && !signaturePreferences.getTimestampUrl().equals("") ) {
				
				XAdESTDetachedSignature signature = new XAdESTDetachedSignature(path, signaturePreferences);
				document = signature.execute();
				
			} else {					
				XAdESBESDetachedSignature signature = new XAdESBESDetachedSignature(path, signaturePreferences);
				document = signature.execute();
			}
			
		} else {
			// de momento solo detached
			return null;
		}
		
		return document;	
	}
	
	
	/**
	 * Para firmas de un archivo. Si recibe un sinadurazip refirma, añade una firma nueva al empaquetado. 
	 * 
	 * @param filePath
	 * @param signaturePreferences
	 * 
	 * @return sinadurazip
	 * @throws OCSPUnknownUrlException 
	 * @throws OCSPIssuerRequiredException 
	 * @throws ConnectionException 
	 * @throws OCSPCoreException 
	 * @throws RevokedException 
	 * @throws CertificateNotYetValidException 
	 * @throws CertificateExpiredException 
	 */
	public static byte[] signArchiver(String filePath, XadesSignaturePreferences signaturePreferences) throws XadesSignatureException,
			OCSPUnknownUrlException, CertificateExpiredException, CertificateNotYetValidException, RevokedException, OCSPCoreException,
			ConnectionException, OCSPIssuerRequiredException {

		// TODO devolver un outputstream en los sars para que no de outofmemory
		try {
			try {
				Archiver archiver = new Archiver(filePath);
				String path = archiver.getDocument();
				byte[] signature = signDetached(path, signaturePreferences);
				archiver.addSignature(signature);
				byte[] output = archiver.generate();
				archiver.close();
				
				return output;
	
			} catch (UknownArchiverException e) {
				
				// file
				byte[] signature = signDetached(filePath, signaturePreferences);
				
				if (signaturePreferences.isGenerateArchiver()) {
					Archiver archiver = new Archiver();
					archiver.addDocument(filePath);
					archiver.addSignature(signature);
					byte[] output = archiver.generate();
					archiver.close();
					
					return output;
				} else {
					return signature;
				}
			}
			
		} catch (ArchiverException e) {
			throw new XadesSignatureException(e);
		}
	}

	public static List<XadesSignatureInfo> validateCxsig(XadesValidator xadesValidator, InputStream cxsig,
			ValidationPreferences validationPreferences) throws XadesValidationFatalException {

		try {
			List<XadesSignatureInfo> results = new ArrayList<XadesSignatureInfo>();
			CxsigArchiver cxsigArchiver = new CxsigArchiver(cxsig);
			String xmlPath = cxsigArchiver.getSignature();
			List<String> documents = cxsigArchiver.getDocuments();
			Map<String, String> documentMap = new HashMap<String, String>(); // <Nombre, Path>
			for (String document : documents) {
				File file = new File(document);
				documentMap.put(file.getName(), file.getAbsolutePath());
			}
			results = validateDigidoc(xadesValidator, xmlPath, documentMap, validationPreferences);
			cxsigArchiver.close();
			
			return results;

		} catch (UknownArchiverException e) {
			throw new XadesValidationFatalException(e);
		} catch (ArchiverException e) {
			throw new XadesValidationFatalException(e);
		}
	}
	
	/**
	 * @param xadesValidator
	 * @param xmlPath
	 * @param documents es un Map <Nombre, Path> para los documentos externos (detached).
	 * @param ksCache
	 * @param ksTrust
	 * @return
	 * @throws XadesValidationFatalException
	 */
	public static List<XadesSignatureInfo> validateDigidoc(XadesValidator xadesValidator, String xmlPath,
			Map<String, String> documents, ValidationPreferences validationPreferences)
			throws XadesValidationFatalException {
		
		try {
			
			List<XadesSignatureInfo> results = new ArrayList<XadesSignatureInfo>();
			
			// 1- validar DIGIDOC (simplemente integridad de los documentos)
			List<DataFile> documentPaths = DigidocUtil.getDataFiles(xmlPath);

			for (DataFile dataFile : documentPaths) {
				
				String docPath = documents.get(dataFile.getFilename());
				
				MessageDigest md = MessageDigest.getInstance("SHA-1");
		        FileInputStream fis = new FileInputStream(docPath);
		        byte[] dataBytes = new byte[1024];
		        int nread = 0; 
		        while ((nread = fis.read(dataBytes)) != -1) {
		          md.update(dataBytes, 0, nread);
		        }
		        byte[] mdbytes = md.digest();
		        
		        String calculatedDigest = Base64.encode(mdbytes);
		        
		        if (!calculatedDigest.equals(dataFile.getDigestValue())) {
		        	
		        	XadesSignatureInfo xadesSignatureInfo = new XadesSignatureInfo();
					xadesSignatureInfo.setValidate(false);
					xadesSignatureInfo.setResultado(ResultadoEnum.INVALID);
					xadesSignatureInfo.setLog("Firma invalida. El documento " + dataFile.getFilename() + " ha sido modificado.");
					results.add(xadesSignatureInfo);
					
					return results;
		        }	
			}
			
			// 2- validar XADES
			List<XadesSignatureInfo> tmpResults = validateXml(xadesValidator, xmlPath, null, validationPreferences);
			for (XadesSignatureInfo resultadoValidacion : tmpResults) {
				results.add(resultadoValidacion);
			}
			
			return results;
			
		} catch (NoSuchAlgorithmException e) {
			throw new XadesValidationFatalException(e);
		} catch (FileNotFoundException e) {
			throw new XadesValidationFatalException(e);
		} catch (IOException e) {
			throw new XadesValidationFatalException(e);
		} catch (DigidocException e) {
			throw new XadesValidationFatalException(e);
		}
	}
	
	
	public static List<XadesSignatureInfo> validateArchiver(XadesValidator xadesValidator, InputStream is,
			ValidationPreferences validationPreferences) throws XadesValidationFatalException {
		
		try {
			// TODO no escribir en FS, hay que corregir antes el check de la extension (aunque creo que luego el unzip si es
			// necesario hacerlo en FS).
			
			File tmp_base = new File(System.getProperty("java.io.tmpdir"));
			String tmpPath = tmp_base.getAbsolutePath() + File.separatorChar + System.currentTimeMillis();
			File tmpFile = new File(tmpPath);
			tmpFile.mkdir();
			String filePath = tmpPath + File.separatorChar + "fichero.sar";
			OutputStream os = new FileOutputStream(filePath);
			IOUtils.copy(is, os);
			List<XadesSignatureInfo> list = validateArchiver(xadesValidator, filePath, validationPreferences);
			FileUtil.deleteDir(tmpPath);
			
			return list;
			
		} catch (IOException e) {
			throw new XadesValidationFatalException(e);
		}
	}
	
	/**
	 * Valida empaquetados SAR
	 * 
	 * @param xadesValidator
	 * @param filePath
	 * @param ksCache
	 * @param ksTrust
	 * @return
	 * @throws XadesValidationFatalException
	 */
	public static List<XadesSignatureInfo> validateArchiver(XadesValidator xadesValidator, String filePath,
			ValidationPreferences validationPreferences) throws XadesValidationFatalException {

		try {
			// el sar
			Archiver archiver = new Archiver(filePath);
			String[] signaturePaths = archiver.getSignatures();
			String documentPath = archiver.getDocument();
			List<XadesSignatureInfo> results = new ArrayList<XadesSignatureInfo>();
			for (String xmlPath : signaturePaths) {
				List<XadesSignatureInfo> tmpResults = validateXml(xadesValidator, xmlPath, documentPath, validationPreferences);
				for (XadesSignatureInfo resultadoValidacion : tmpResults) {
					results.add(resultadoValidacion);
				}
			}
			archiver.close();
			return results;

		} catch (UknownArchiverException e) {
			throw new XadesValidationFatalException(e);
		} catch (ArchiverException e) {
			throw new XadesValidationFatalException(e);
		}
	}

	/*
	 * No se pueden hacer ahora todos los polimorfismos deseados debido a las difrencias entre los dos validadores disponibles. 
	 * El de sinadura requiere basePath (String) y el de zain los documents.
	 * 
	 * TODO Habria antes que hacer un refactor.
	 * TODO pasar document --> Map de documents
	 * 
	 */
	
	/**
	 * Como se parte de un InputStream no va a encontrar documentos externos. De modo que NO valida firmas detached.
	 * 
	 * @param xadesValidator
	 * @param xml
	 * @param validationPreferences
	 * @return
	 * @throws XadesValidationFatalException
	 */
	public static List<XadesSignatureInfo> validateXml(XadesValidator xadesValidator, InputStream xml,
			ValidationPreferences validationPreferences) throws XadesValidationFatalException {

		return validateXml(xadesValidator, xml, null, null, validationPreferences);	
	}

	public static List<XadesSignatureInfo> validateXml(XadesValidator xadesValidator, String xmlPath, String documentPath,
			ValidationPreferences validationPreferences) throws XadesValidationFatalException {

		try {
			URI file = new URI(FileUtil.normaliceLocalURI(xmlPath));
			URI baseUri = FileUtil.getParentFolder(file);
			String baseUtf8 = baseUri.toASCIIString();
			InputStream xmlIs = FileUtil.getInputStreamFromURI(xmlPath);
			
			InputStream docIs = null;
			if (documentPath != null) {
				docIs = FileUtil.getInputStreamFromURI(documentPath);
			}
			
			return validateXml(xadesValidator, xmlIs, docIs, baseUtf8, validationPreferences);
			
		} catch (URISyntaxException e) {
			throw new XadesValidationFatalException(e);
		} catch (IOException e) {
			throw new XadesValidationFatalException(e);
		}
		
	}
	
	private static List<XadesSignatureInfo> validateXml(XadesValidator xadesValidator, InputStream xml, InputStream document,
			String baseUtf8, ValidationPreferences validationPreferences) throws XadesValidationFatalException {
			
		return xadesValidator.validarFichero(xml, document, baseUtf8, validationPreferences);
	}

}




