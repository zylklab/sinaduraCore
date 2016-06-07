/*
 * LICENCIA LGPL:
 * 
 * Esta librería es Software Libre; Usted puede redistribuirlo y/o modificarlo
 * bajo los términos de la GNU Lesser General Public License (LGPL)
 * tal y como ha sido publicada por la Free Software Foundation; o
 * bien la versión 2.1 de la Licencia, o (a su elección) cualquier versión posterior.
 * 
 * Esta librería se distribuye con la esperanza de que sea útil, pero SIN NINGUNA
 * GARANTÍA; tampoco las implícitas garantías de MERCANTILIDAD o ADECUACIÓN A UN
 * PROPÓSITO PARTICULAR. Consulte la GNU Lesser General Public License (LGPL) para más
 * detalles
 * 
 * Usted debe recibir una copia de la GNU Lesser General Public License (LGPL)
 * junto con esta librería; si no es así, escriba a la Free Software Foundation Inc.
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA.
 * 
 */
package net.esle.sinadura.core.xades;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import net.esle.sinadura.core.certificate.CertificateUtil;
import net.esle.sinadura.core.exceptions.ConnectionException;
import net.esle.sinadura.core.exceptions.OCSPCoreException;
import net.esle.sinadura.core.exceptions.OCSPIssuerRequiredException;
import net.esle.sinadura.core.exceptions.OCSPUnknownUrlException;
import net.esle.sinadura.core.exceptions.RevokedException;
import net.esle.sinadura.core.exceptions.XadesSignatureException;
import net.esle.sinadura.core.model.KsSignaturePreferences;
import net.esle.sinadura.core.model.XadesSignaturePreferences;
import net.esle.sinadura.core.validate.CertPathUtil;
import net.esle.sinadura.core.validate.OcspUtil;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.xades.DataToSign;
import es.mityc.firmaJava.libreria.xades.FirmaXML;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.keystore.KSStore;
import es.mityc.javasign.trust.TrustAbstract;


public abstract class GenericXMLSignature {
	
	private static Log log = LogFactory.getLog(GenericXMLSignature.class);
	
	/**
	 * Hay dos opciones a la hora de firmar: 
	 * 1- Se indicar el keystore y el alias, de forma que en la accion de firma se obtiene
	 * la privateKey. private KsSignaturePreferences ksSignaturePreferences = null;
	 * 2- Se indica directamente la privateKey, obtenida previamente (cryptoApplet).
	 * 
	 * @return
	 * @throws XadesSignatureException
	 * @throws OCSPUnknownUrlException
	 * @throws RevokedException
	 * @throws OCSPCoreException
	 * @throws ConnectionException
	 * @throws OCSPIssuerRequiredException
	 * @throws CertificateExpiredException
	 * @throws CertificateNotYetValidException
	 */
	public byte[] execute() throws XadesSignatureException, OCSPUnknownUrlException, RevokedException, OCSPCoreException,
			ConnectionException, OCSPIssuerRequiredException, CertificateExpiredException, CertificateNotYetValidException {

		
		// CARGA KS
		KeyStore ks = getSignaturePreferences().getKsSignaturePreferences().getKs();
		String alias = getSignaturePreferences().getKsSignaturePreferences().getAlias();

		X509Certificate certificate = null;
		PrivateKey privateKey = null;
		
		try {
			
			// certificate y chain
			Certificate[] chain;
			if (getSignaturePreferences().getPrivateKey() != null && getSignaturePreferences().getCertificate() != null) {
				
				certificate = getSignaturePreferences().getCertificate();
				chain = new Certificate[1];
				chain[0] = certificate;
				
			} else {
				// aqui no suelen estar los certificados raiz (en el caso de pkcs11 o pkcs12)
				chain = ks.getCertificateChain(alias);
				certificate = (X509Certificate)chain[0];
			}
			
			// check certificate		
			certificate.checkValidity();
			
			// completar chain
			if (getSignaturePreferences().getKsCache() != null) {
				
				CertPath certPath = CertPathUtil.convert2CertPath(chain);
				Set<CertStore> certStores = new HashSet<CertStore>();
				certStores.add(CertPathUtil.convert2CertStore(getSignaturePreferences().getKsCache()));
				certPath = CertPathUtil.completeChain(certPath, certStores);
				List<Certificate> tmpList = (List<Certificate>)certPath.getCertificates();
				chain = (Certificate[])tmpList.toArray(new Certificate[tmpList.size()]);
			}
			
			// ocsp
			if (getSignaturePreferences().getAddOCSP()) {
				if (chain.length >= 2) {
					String url = CertificateUtil.getOCSPURL((X509Certificate) chain[0]);	
					OcspUtil.getStatus((X509Certificate) chain[0], (X509Certificate) chain[1], url, new Date());
				} else {
					throw new OCSPIssuerRequiredException();
				}
			}
			
			// privateKey
			if (getSignaturePreferences().getPrivateKey() != null) {
				
				privateKey = getSignaturePreferences().getPrivateKey();
				
			} else {
				KeyStore.PrivateKeyEntry keyEntry = null;
				keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, getSignaturePreferences().getKsSignaturePreferences()
						.getPasswordProtection());
				privateKey = keyEntry.getPrivateKey();
			}

		} catch (KeyStoreException e) {
			throw new XadesSignatureException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new XadesSignatureException(e);
		} catch (UnrecoverableEntryException e) {
			throw new XadesSignatureException(e);
		} catch (NoSuchProviderException e) {
			throw new XadesSignatureException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new XadesSignatureException(e);
		} catch (java.security.cert.CertStoreException e) {
			throw new XadesSignatureException(e);
		}  catch (CertificateException e) {
			if (e instanceof CertificateExpiredException) {
				throw (CertificateExpiredException)e;
			} else if (e instanceof CertificateNotYetValidException) {
				throw (CertificateNotYetValidException)e;
			} else {
				throw new XadesSignatureException(e);
			}
		}


		Provider provider;
		if (getSignaturePreferences().getPrivateKey() != null && getSignaturePreferences().getProvider() != null) {

			provider = getSignaturePreferences().getProvider();
			
		} else {
			
			// solo mantengo lo del storeManager para obtener el provider, por lo demas se podria borrar ese codigo
			IPKStoreManager storeManager = getPKStoreManager();
			provider = storeManager.getProvider(certificate);
		}

		/*
		 * Creación del objeto que contiene tanto los datos a firmar como la configuración del tipo de firma
		 */
		DataToSign dataToSign = createDataToSign();

		// Firmamos el documento
		Document docSigned = null;
		try {
			/*
			 * Creación del objeto encargado de realizar la firma
			 */
			FirmaXML firma = createFirmaXML();
			TrustAbstract truster = new KeystoreTruster(getSignaturePreferences().getKsCache()); // le paso el Trust ks para la realizacion de las ocsps del tsa
			String timestampOcspUrl = getSignaturePreferences().getTimestampOcspUrl();
			boolean xlOcspAddAll = getSignaturePreferences().isXlOcspAddAll();
			
			Object[] res = firma.signFile(certificate, dataToSign, privateKey, provider, truster, timestampOcspUrl, xlOcspAddAll);
			docSigned = (Document) res[0];
			
		} catch (Exception e) {
			throw new XadesSignatureException(e);
		}

		ByteArrayOutputStream os = new ByteArrayOutputStream();
		
		UtilidadTratarNodo.saveDocumentToOutputStream(docSigned, os, true);

		return os.toByteArray();
	}

	/**
	 * <p>
	 * Crea el objeto DataToSign que contiene toda la información de la firma que se desea realizar. Todas las implementaciones deberán
	 * proporcionar una implementación de este método
	 * </p>
	 * 
	 * @return El objeto DataToSign que contiene toda la información de la firma a realizar
	 */
	protected abstract DataToSign createDataToSign() throws XadesSignatureException, OCSPUnknownUrlException;

	protected abstract XadesSignaturePreferences getSignaturePreferences();

	/**
	 * <p>
	 * Crea el objeto <code>FirmaXML</code> con las configuraciones necesarias que se encargará de realizar la firma del documento.
	 * </p>
	 * <p>
	 * En el caso más simple no es necesaria ninguna configuración específica. En otros casos podría ser necesario por lo que las
	 * implementaciones concretas de las diferentes firmas deberían sobreescribir este método (por ejemplo para añadir una autoridad de
	 * sello de tiempo en aquellas firmas en las que sea necesario)
	 * <p>
	 * 
	 * 
	 * @return firmaXML Objeto <code>FirmaXML</code> configurado listo para usarse
	 */
	protected FirmaXML createFirmaXML() {
		
		FirmaXML firmaXML = new FirmaXML();
		// locale de los mensajes de error
		Locale locale = Locale.getDefault();
		firmaXML.setLocale(locale.getLanguage());
		return firmaXML;
	}


	/**
	 * <p>
	 * Devuelve el <code>Document</code> correspondiente al <code>resource</code> pasado como parámetro
	 * </p>
	 * 
	 * @param resource
	 *            El recurso que se desea obtener
	 * @return El <code>Document</code> asociado al <code>resource</code>
	 */
	protected Document getDocument(String resource) throws XadesSignatureException {

		Document doc = null;
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		try {
			InputStream is = new FileInputStream(resource);
			doc = dbf.newDocumentBuilder().parse(is);
			
		} catch (ParserConfigurationException e) {
			throw new XadesSignatureException(e);
		} catch (SAXException e) {
			throw new XadesSignatureException(e);
		} catch (IOException e) {
			throw new XadesSignatureException(e);
		}
		return doc;
	}
	
	/**
	 * <p>
	 * Devuelve el <code>Document</code> correspondiente al <code>resource</code> pasado como parámetro
	 * </p>
	 * 
	 * @param resource
	 *            El recurso que se desea obtener
	 * @return El <code>Document</code> asociado al <code>resource</code>
	 */
	protected Document getDocument(InputStream is) throws XadesSignatureException {

		Document doc = null;
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		try {
			doc = dbf.newDocumentBuilder().parse(is);
			
		} catch (ParserConfigurationException e) {
			throw new XadesSignatureException(e);
		} catch (SAXException e) {
			throw new XadesSignatureException(e);
		} catch (IOException e) {
			throw new XadesSignatureException(e);
		}
		return doc;
	}

	/**
	 * <p>
	 * Devuelve el contenido del documento XML correspondiente al <code>resource</code> pasado como parámetro
	 * </p>
	 * como un <code>String</code>
	 * 
	 * @param resource
	 *            El recurso que se desea obtener
	 * @return El contenido del documento XML como un <code>String</code>
	 */
	protected String getDocumentAsString(String resource) throws XadesSignatureException {
		
		Document doc = getDocument(resource);
		TransformerFactory tfactory = TransformerFactory.newInstance();
		Transformer serializer;
		StringWriter stringWriter = new StringWriter();
		try {
			serializer = tfactory.newTransformer();
			serializer.transform(new DOMSource(doc), new StreamResult(stringWriter));
		} catch (TransformerException e) {
			throw new XadesSignatureException(e);
		}

		return stringWriter.toString();
	}

	/**
	 * <p>
	 * Devuelve el gestor de claves que se va a utilizar
	 * </p>
	 * 
	 * @return El gestor de claves que se va a utilizar</p>
	 */
	private IPKStoreManager getPKStoreManager() {

		KeyStore ks = getSignaturePreferences().getKsSignaturePreferences().getKs();
		IPKStoreManager storeManager = new KSStore(ks, null);
		return storeManager;
	}


}
