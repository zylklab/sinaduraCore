
package net.esle.sinadura.core.xades;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import net.esle.sinadura.core.exceptions.XadesValidationFatalException;
import net.esle.sinadura.core.model.ChainInfo;
import net.esle.sinadura.core.model.ValidationPreferences;
import net.esle.sinadura.core.model.XadesSignatureInfo;
import net.esle.sinadura.core.util.LanguageUtil;
import net.esle.sinadura.core.validate.CertPathUtil;
import net.esle.sinadura.core.validate.TimestampUtil;
import net.esle.sinadura.core.xades.ext.ValidarFirmaXML;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.I18n;
import es.mityc.firmaJava.libreria.xades.EnumFormatoFirma;
import es.mityc.firmaJava.libreria.xades.ExtraValidators;
import es.mityc.firmaJava.libreria.xades.ResultadoValidacion;
import es.mityc.firmaJava.libreria.xades.errores.FirmaXMLError;
import es.mityc.javasign.trust.TrustAbstract;
import es.mityc.javasign.xml.xades.policy.IValidacionPolicy;


public class CompleteValidation {

	private static Log log = LogFactory.getLog(CompleteValidation.class);

	public static List<XadesSignatureInfo> validarFichero(InputStream fichero, String baseUri, ValidationPreferences validationPreferences)
			throws XadesValidationFatalException {
		
        // Política de ejemplo
//		ArrayList<IValidacionPolicy> arrayPolicies = new ArrayList<IValidacionPolicy>(1);
//        IValidacionPolicy policy = new MyPolicy();
//        arrayPolicies.add(policy);
        ArrayList<IValidacionPolicy> arrayPolicies = null;

        // Validacion extra de confianza de certificados
//        TrustAbstract truster = TrustFactory.getInstance().getTruster(TRUSTER_NAME);
        TrustAbstract truster = new KeystoreTruster(validationPreferences.getKsTrust());
		
        // Validadores extra
        ExtraValidators validator = new ExtraValidators(arrayPolicies, null, truster);

        // Se declara la estructura de datos que almacenara el resultado de la validacion
        List<ResultadoValidacion> results = null;
		
        // Se convierte el InputStream a Document
        Document doc = parseaDoc(fichero);
        
		
		// Se instancia el validador y se realiza la validación
		try {
			ValidarFirmaXML vXml = new ValidarFirmaXML();
			// locale de los mensajes de error
			Locale locale = LanguageUtil.getLocale();
			vXml.setLocale(locale.getLanguage());
			// resolver
			vXml.addResolver(new Utf8ResolverBigLocalFileSystem());
			results = vXml.validar(doc, baseUri, validator, validationPreferences.isValidateEpesPolicy());
			
		} catch (FirmaXMLError e) {
			
			if (e.getMessage().equals(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR2))) {
				// no se encuentra el nodo de firma -> documento no firmado
				results = new ArrayList<ResultadoValidacion>();
			} else {
				throw new XadesValidationFatalException(e);
			}
		}

		
        ResultadoValidacion result = null;
        Iterator<ResultadoValidacion> it = results.iterator();
        
        List<XadesSignatureInfo> xadesSignatureInfos = new ArrayList<XadesSignatureInfo>();
        
		while (it.hasNext()) {
			
			result = it.next();
			
			// convertir a XadesSignatureInfo
			XadesSignatureInfo xadesSignatureInfo = new XadesSignatureInfo();
			xadesSignatureInfo.setValidate(result.isValidate());
			xadesSignatureInfo.setResultado(result.getResultado());
			xadesSignatureInfo.setLog(result.getLog());
			xadesSignatureInfo.setNivelValido(result.getNivelValido());
			xadesSignatureInfo.setEnumNivel(result.getEnumNivel());
			xadesSignatureInfo.setDoc(result.getDoc());
			xadesSignatureInfo.setDatosFirma(result.getDatosFirma());
			xadesSignatureInfo.setBaseURI(result.getBaseURI());
			xadesSignatureInfo.setFirmados(result.getFirmados());
			xadesSignatureInfo.setContrafirmadoPor(result.getContrafirmadoPor());
			xadesSignatureInfo.setCertStatus(result.getCertStatus());
			
			try {
				// COMPROBACION ADICIONAL DEL ESTADO DE REVOCACION
				// se hace siempre que no sean firmas XL completamente validas.
				// Ademas de comprobar el estado de revocacion de las firmas bes y t, iguala tambien los mensajes de error en las XL no
				// validas. Debido a esto es posible que se cambie el orden de ciertos errores. Por otra parte puede llegar a penalizar el
				// rendimiento, ya que las firmas erroneas se vuelven a validar.
				if (xadesSignatureInfo.getDatosFirma() != null && xadesSignatureInfo.getDatosFirma().getTipoFirma() != null
						&& xadesSignatureInfo.getDatosFirma().getTipoFirma().getTipoXAdES() != null
						&& xadesSignatureInfo.getDatosFirma().getCadenaFirma() != null
						&& xadesSignatureInfo.getDatosFirma().getCadenaFirma().getCertificates() != null
						&& xadesSignatureInfo.getDatosFirma().getFechaFirma() != null) {
				
					if (!xadesSignatureInfo.isValidate()
							|| !xadesSignatureInfo.getDatosFirma().getTipoFirma().getTipoXAdES().equals(EnumFormatoFirma.XAdES_XL)) {
						
						X509Certificate signer = (X509Certificate) xadesSignatureInfo.getDatosFirma().getCadenaFirma().getCertificates()
								.get(0);
						Date date = xadesSignatureInfo.getDatosFirma().getFechaFirma();
						
						Set<CertStore> certStoreList = new HashSet<CertStore>();
						certStoreList.add(CertPathUtil.convert2CertStore(xadesSignatureInfo.getDatosFirma().getCadenaFirma()));
						certStoreList.add(CertPathUtil.convert2CertStore(validationPreferences.getKsCache()));
						
						// validar chain
						ChainInfo chainInfo = CertPathUtil.validateChain(signer, validationPreferences.getKsTrust(), certStoreList, date, validationPreferences.isCheckRevocation());
						
						xadesSignatureInfo.setChainInfo(chainInfo);
					}
				}
				
			} catch (InvalidAlgorithmParameterException e) {
				throw new XadesValidationFatalException(e);
			} catch (NoSuchAlgorithmException e) {
				throw new XadesValidationFatalException(e);
			} catch (KeyStoreException e) {
				throw new XadesValidationFatalException(e);
			} catch (CertificateException e) {
				throw new XadesValidationFatalException(e);
			} catch (CertStoreException e) {
				throw new XadesValidationFatalException(e);
			} catch (NoSuchProviderException e) {
				throw new XadesValidationFatalException(e);
			}
			
			
			// setear cadena completa del timestamp
			if (xadesSignatureInfo.getDatosFirma() != null && result.getDatosFirma().getDatosSelloTiempo() != null
					&& result.getDatosFirma().getDatosSelloTiempo().size() > 0) {
			
				try {
					TimeStampToken token = result.getDatosFirma().getDatosSelloTiempo().get(0).getTst();
					
					CertStore certStoreTimestamp = token.getCertificatesAndCRLs("Collection", null);
					Set<CertStore> certStoreList = new HashSet<CertStore>();
					certStoreList.add(certStoreTimestamp);
					certStoreList.add(CertPathUtil.convert2CertStore(validationPreferences.getKsCache()));
					
					X509Certificate signer = TimestampUtil.verifyTimestampCertificate(token, certStoreList, null);
					
					if (signer != null) {
						
						List<X509Certificate> chain = new ArrayList<X509Certificate>();
						chain.add(signer);
						CertPath certPath = CertPathUtil.convert2CertPath(chain);
						certPath = CertPathUtil.completeChain(certPath, certStoreList);
						List<X509Certificate> tsChain = (List<X509Certificate>) certPath.getCertificates(); 
						xadesSignatureInfo.setTsChain(tsChain);
					}
					
				} catch (CertificateException e) {
					log.error(e);
				} catch (KeyStoreException e) {
					log.error(e);
				} catch (InvalidAlgorithmParameterException e) {
					log.error(e);
				} catch (NoSuchAlgorithmException e) {
					log.error(e);
				} catch (NoSuchProviderException e) {
					log.error(e);
				} catch (CMSException e) {
					log.error(e);
				} catch (CertStoreException e) {
					log.error(e);
				}
			}
			
			
			printResult(xadesSignatureInfo);
			
			xadesSignatureInfos.add(xadesSignatureInfo);	
		}
		
		return xadesSignatureInfos;
	}
	
	
	public static void printResult(XadesSignatureInfo xadesSignatureInfo) {
		
		// mostrar info
		if (xadesSignatureInfo.isValidate()) {
			// El método getNivelValido devuelve el último nivel XAdES válido
			log.info(xadesSignatureInfo.getNivelValido());
			log.info("Resultado: " + xadesSignatureInfo.getResultado());
			log.info("BaseUri: " + xadesSignatureInfo.getBaseURI().toString());
			log.info("Certificado: "
					+ ((X509Certificate) xadesSignatureInfo.getDatosFirma().getCadenaFirma().getCertificates().get(0)).getSubjectDN());
			log.info("Firmado el: " + xadesSignatureInfo.getDatosFirma().getFechaFirma());
			log.info("Estado de confianza: " + xadesSignatureInfo.getDatosFirma().esCadenaConfianza());
//			log.info("Nodos firmados: " + xadesSignatureInfo.getFirmados());
			log.info("log: " + xadesSignatureInfo.getLog());

		} else {
			log.info("Resultado: " + xadesSignatureInfo.getResultado());
			log.info("BaseUri: " + xadesSignatureInfo.getBaseURI().toString());
			if (xadesSignatureInfo.getDatosFirma() != null && xadesSignatureInfo.getDatosFirma().getTipoFirma() != null) {
				log.info("Tipo de firma: " + xadesSignatureInfo.getDatosFirma().getTipoFirma().getTipoXAdES());
			}
			// El método getLog devuelve el mensaje de error que invalidó la firma
			log.info("log: " + xadesSignatureInfo.getLog());
			if (xadesSignatureInfo.getCertStatus() != null) {
				log.info("certStatus: " + xadesSignatureInfo.getCertStatus().getStatus());
			} 
		}
	}

    
	private static Document parseaDoc(InputStream fichero) throws XadesValidationFatalException {

		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(fichero);
			return doc;
			
		} catch (SAXException ex) {
			log.error(ex);
			throw new XadesValidationFatalException("El documento no es un xml valido");
		} catch (IOException ex) {
			log.error(ex);
			throw new XadesValidationFatalException("El documento no es un xml valido");
		} catch (ParserConfigurationException ex) {
			log.error(ex);
			throw new XadesValidationFatalException("El documento no es un xml valido");
		}
	}
}