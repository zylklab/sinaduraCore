
package net.esle.sinadura.core.xades.validator.impl;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import net.esle.sinadura.core.exceptions.XadesValidationFatalException;
import net.esle.sinadura.core.model.ValidationPreferences;
import net.esle.sinadura.core.model.XadesSignatureInfo;
import net.esle.sinadura.core.validate.CertPathUtil;
import net.esle.sinadura.core.xades.validator.XadesValidator;
import net.esle.sinadura.ee.EEModulesManager;
import net.esle.sinadura.ee.interfaces.ZainEEModule;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Base64;

import com.izenpe.zain.client.ZainConfig;
import com.izenpe.zain.cliente.util.Constantes;
import com.safelayer.trustedx.client.smartwrapper.SmartSignatureResult;
import com.safelayer.trustedx.client.smartwrapper.SmartStamp;
import com.safelayer.trustedx.client.smartwrapper.SmartVerifyResponse;

import es.mityc.firmaJava.libreria.xades.DatosFirma;
import es.mityc.firmaJava.libreria.xades.DatosSelloTiempo;
import es.mityc.firmaJava.libreria.xades.DatosTipoFirma;
import es.mityc.firmaJava.libreria.xades.EnumFormatoFirma;
import es.mityc.firmaJava.libreria.xades.ResultadoEnum;
import es.mityc.firmaJava.trust.ConfianzaEnum;


public class ZainXadesValidator implements XadesValidator {

	private static Log log = LogFactory.getLog(ZainXadesValidator.class);

	private ZainConfig zainConfig;
	private String endPoint;
	private String language;
	

	/**
	 * 
	 * El proxy unicamente se habilita si hay un ProxySelector configurado en el sistema. En tal caso hay que especifcar el
	 * proxyUser y el proxyPass (si para el endpoint de zain se requiere).
	 *
	 * @param endPoint
	 * @param truststorePath
	 * @param truststorePassword
	 * @param keystorePath
	 * @param keystorePassword
	 * @param proxyUser
	 * @param proxyPass
	 * @param logActive
	 * @param requestLogSavePath
	 * @param responseLogSavePath
	 * @param language
	 * @throws XadesValidationFatalException
	 */
	public void configure(String endPoint, String truststorePath, String truststorePassword, String keystorePath,
			String keystorePassword, String proxyUser, String proxyPass, boolean logActive, String requestLogSavePath,
			String responseLogSavePath, String language) throws XadesValidationFatalException {
		
		// ZAIN_ENDPOINT
		this.endPoint = endPoint;
		this.language = language;
		
		// CONFIG-
		zainConfig = new ZainConfig();
		
		zainConfig.setAuthenticationPolicy("urn:izenpe:tws:policies:authentication:psf");

		zainConfig.setTruststoreActive(true);
		zainConfig.setTruststorePath(truststorePath);
		zainConfig.setTruststorePassword(truststorePassword);

		zainConfig.setKeystoreActive(true);
		zainConfig.setKeystorePath(keystorePath);
		zainConfig.setKeystorePassword(keystorePassword);
		zainConfig.setKeystoreType("PKCS12");

		// proxy
		try {
			ProxySelector myProxySelector = ProxySelector.getDefault();
			if (myProxySelector != null) {
				URI uri = new URI(endPoint);
				List<Proxy> proxies = myProxySelector.select(uri);
				int i = 0;
				for (Proxy proxy : proxies) {
					log.info("proxy.toString: " + proxy.toString());
					log.info("proxy.type: " + proxy.type().toString());
					if (i == 0) {
						if (proxy.address() != null) {
							log.info("configurando proxy para la peticion a zain: " + proxy.address().toString());
							InetSocketAddress addr = ((InetSocketAddress) proxy.address());
							zainConfig.setProxyActive(true);
							zainConfig.setProxyHost(addr.getHostName());
							zainConfig.setProxyPort(String.valueOf(addr.getPort()));
							zainConfig.setProxyUsername(proxyUser);
							zainConfig.setProxyPassword(proxyPass);
				        }
					}
				}
			}
		} catch (URISyntaxException e) {
			log.error("", e);
		}

		int timeout = 120000;
		zainConfig.setTimeout(timeout); // 2 minutos
		log.info("zain timeout (ms): " + timeout);

		zainConfig.setRequestLogActive(logActive);
		zainConfig.setRequestLogSavePath(requestLogSavePath);
		zainConfig.setResponseLogActive(logActive);
		zainConfig.setResponseLogSavePath(responseLogSavePath);
	}
	
	@Override
	public List<XadesSignatureInfo> validarFichero(InputStream signature, InputStream document, String baseUri,
			ValidationPreferences validationPreferences) throws XadesValidationFatalException {

		log.info("comenzando la validacion en zain");
		
		try {	
			// 1- VALIDACION ZAIN
			ZainEEModule zainModule = EEModulesManager.getZainModule();
			zainModule.configure(zainConfig, endPoint, language);
			SmartVerifyResponse smartVerifyResp = zainModule.validarFichero(signature, document);
		
			// 2- PARSEO DE LA RESPUESTA
			// init
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			Set<CertStore> certStores = new HashSet<CertStore>();
			CertStore certStore = CertPathUtil.convert2CertStore(validationPreferences.getKsCache());
			certStores.add(certStore);
			

			List<XadesSignatureInfo> xadesSignatureInfos = new ArrayList<XadesSignatureInfo>();	
		
			// convertir a XadesSignatureInfo
			XadesSignatureInfo xadesSignatureInfo = new XadesSignatureInfo();
			
			log.info("getResultMajor: " + smartVerifyResp.getResultMajor());
			log.info("getResultMinor: " + smartVerifyResp.getResultMinor());
			log.info("getResultMessage: " + smartVerifyResp.getResultMessage());
			
			// Se comprueba la validez de la respuesta de Verificacion de firma XMLDSig.
			if (Constantes.RMAJOR_SUCCESS.equals((smartVerifyResp.getResultMajor()))
					&& Constantes.RMINOR_SUCCESS.equals(smartVerifyResp.getResultMinor())) {
				
				xadesSignatureInfo.setValidate(true);
				xadesSignatureInfo.setResultado(ResultadoEnum.VALID);
				
			} else {
				xadesSignatureInfo.setValidate(false);
				xadesSignatureInfo.setResultado(ResultadoEnum.INVALID);
				xadesSignatureInfo.setLog(smartVerifyResp.getResultMessage());
			}
			
			if (smartVerifyResp.getNumberSignatures() > 0) {
			
				// TODO de momento solo una firma
				SmartSignatureResult smartSignatureResult = smartVerifyResp.getSignature(0);
				DatosFirma datosFirma = new DatosFirma();
				
				// PERFIL
				log.info("getSignatureType: " + smartSignatureResult.getSignatureType());
				log.info("getSignatureForm: " + smartSignatureResult.getSignatureForm());
				
				DatosTipoFirma datosTipoFirma = new DatosTipoFirma();
				if (smartSignatureResult.getSignatureForm().equals("ES-A")) {
					xadesSignatureInfo.setEnumNivel(EnumFormatoFirma.XAdES_A);
					datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_A);
				} else if (smartSignatureResult.getSignatureForm().equals("ES-XL")) {
					xadesSignatureInfo.setEnumNivel(EnumFormatoFirma.XAdES_XL);
					datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_XL);
				} else if (smartSignatureResult.getSignatureForm().equals("ES-X")) { // TODO probar
					xadesSignatureInfo.setEnumNivel(EnumFormatoFirma.XAdES_X);
					datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_X);
				} else if (smartSignatureResult.getSignatureForm().equals("ES-T")) { // TODO probar
					xadesSignatureInfo.setEnumNivel(EnumFormatoFirma.XAdES_T);
					datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_T);
				} else if (smartSignatureResult.getSignatureForm().equals("ES-C")) { // TODO probar
					xadesSignatureInfo.setEnumNivel(EnumFormatoFirma.XAdES_C);
					datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_C);
				} else {
					xadesSignatureInfo.setEnumNivel(EnumFormatoFirma.XAdES_BES);
					datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_BES);
				}
				datosFirma.setTipoFirma(datosTipoFirma);
			
				// Fecha
				datosFirma.setFechaFirma(smartSignatureResult.getSigningTime());
				
				// TSA (global)
				log.info("getTimeStampsResultMajor: " + smartSignatureResult.getTimeStampsResultMajor());
				log.info("getTimeStampsResultMinor: " + smartSignatureResult.getTimeStampsResultMinor());
				log.info("getTimeStampsResultMessage: " + smartSignatureResult.getTimeStampsResultMessage());
				if (smartSignatureResult.getTimeStampsResultMessage() != null && xadesSignatureInfo.getLog() == null) {
					xadesSignatureInfo.setLog(smartSignatureResult.getTimeStampsResultMessage() + " (T-TimeStamp)");
				}
	
				// TSA (1)
				// tsa chain
				SmartStamp smartStamp = smartSignatureResult.getStamp(0);
				if (smartStamp != null) {
					log.info("smartStamp.getResultMajor: " + smartStamp.getResultMajor());
					log.info("smartStamp.getResultMinor: " + smartStamp.getResultMinor());
					log.info("smartStamp.getResultMessage: " + smartStamp.getResultMessage());
					if (smartStamp.getResultMessage() != null && xadesSignatureInfo.getLog() == null) {
						xadesSignatureInfo.setLog(smartStamp.getResultMessage() + " (T-TimeStamp)");
					}
					
					DatosSelloTiempo datosSelloTiempo = new DatosSelloTiempo();
					datosSelloTiempo.setFecha(smartSignatureResult.getSigningTime()); // TODO aqui esta el tiempo del timestamp????
					ArrayList<DatosSelloTiempo> listaDST = new ArrayList<DatosSelloTiempo>();
					listaDST.add(datosSelloTiempo);
					datosFirma.setDatosSelloTiempo(listaDST);
					
					if (smartStamp.getTsaCertificateBinary() != null) {
						byte[] certTSBytes = Base64.decode(smartStamp.getTsaCertificateBinary());
						InputStream in = new ByteArrayInputStream(certTSBytes);
						X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
						X509Certificate[] certPathArray = new X509Certificate[1];
						certPathArray[0] = cert;
						CertPath certPath = CertPathUtil.convert2CertPath(certPathArray);
						certPath = CertPathUtil.completeChain(certPath, certStores);
						xadesSignatureInfo.setTsChain((List<X509Certificate>)certPath.getCertificates());
					}
				}
				
				// CHAIN
				byte[] certBytes = Base64.decode(smartSignatureResult.getSignerCertificateBinary());
				InputStream in = new ByteArrayInputStream(certBytes);
				X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
				X509Certificate[] certPathArray = new X509Certificate[1];
				certPathArray[0] = cert;
				CertPath certPath = CertPathUtil.convert2CertPath(certPathArray);
				certPath = CertPathUtil.completeChain(certPath, certStores);
				
				datosFirma.setCadenaFirma(certPath);
				datosFirma.setEsCadenaConfianza(ConfianzaEnum.CON_CONFIANZA); // lo pongo siempre a confianza porque si hay un
																				// error da igual que este a confianza (mirar el
																				// interpreter).
		
				// Timestamp XADES-X
				log.info("getXType1TimeStampsResultMajor: " + smartSignatureResult.getXType1TimeStampsResultMajor());
				log.info("getXType1TimeStampsResultMinor: " + smartSignatureResult.getXType1TimeStampsResultMinor());
				log.info("getXType1TimeStampsResultMessage: " + smartSignatureResult.getXType1TimeStampsResultMessage());
				if (smartSignatureResult.getXType1TimeStampsResultMessage() != null && xadesSignatureInfo.getLog() == null) {
					xadesSignatureInfo.setLog(smartSignatureResult.getXType1TimeStampsResultMessage() + " (X-TimeStamp)");
				}
				
				// XADES-A (global)
				log.info("getArchiveTimeStampsResultMajor: " + smartSignatureResult.getArchiveTimeStampsResultMajor());
				log.info("getArchiveTimeStampsResultMinor: " + smartSignatureResult.getArchiveTimeStampsResultMinor());
				log.info("getArchiveTimeStampsResultMessage: " + smartSignatureResult.getArchiveTimeStampsResultMessage());
				if (smartSignatureResult.getArchiveTimeStampsResultMessage() != null && xadesSignatureInfo.getLog() == null) {
					xadesSignatureInfo.setLog(smartSignatureResult.getArchiveTimeStampsResultMessage() + " (A-TimeStamp)");
				}
				
				// XADES-A (1)
				SmartStamp archiveStamp = smartSignatureResult.getArchiveStamp(0);
				if (archiveStamp != null) {
					log.info("archiveStamp.getResultMajor: " + archiveStamp.getResultMajor());
					log.info("archiveStamp.getResultMinor: " + archiveStamp.getResultMinor());
					log.info("archiveStamp.getResultMessage: " + archiveStamp.getResultMessage());
					if (archiveStamp.getResultMessage() != null && xadesSignatureInfo.getLog() == null) {
						xadesSignatureInfo.setLog(archiveStamp.getResultMessage() + " (A-TimeStamp)"); 
					}
					
//					if (archiveStamp.getTsaCertificateBinary() != null) {
//						byte[] certTSBytes = Base64.decode(archiveStamp.getTsaCertificateBinary());
//						InputStream inA = new ByteArrayInputStream(certTSBytes);
//						X509Certificate certA = (X509Certificate)certFactory.generateCertificate(inA);
//						log.info("Id del certificado del TS de xades-A: " + certA.getSubjectX500Principal());
//					}
				}

				xadesSignatureInfo.setDatosFirma(datosFirma);
			}
			
			xadesSignatureInfos.add(xadesSignatureInfo);
			
			log.info("validacion en zain finalizada");
		
			return xadesSignatureInfos;
			
		} catch (Exception e) {
			throw new XadesValidationFatalException(e); 
		}
	}
	
}

