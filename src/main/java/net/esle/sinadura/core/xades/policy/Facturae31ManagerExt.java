package net.esle.sinadura.core.xades.policy;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import net.esle.sinadura.core.util.KeystoreUtil;
import net.esle.sinadura.core.xades.KeystoreTruster;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.javasign.i18n.I18nFactory;
import es.mityc.javasign.i18n.II18nManager;
import es.mityc.javasign.xml.xades.policy.facturae.ConstantsFacturaePolicy;
import es.mityc.javasign.xml.xades.policy.facturae.Facturae31Manager;

public class Facturae31ManagerExt extends Facturae31Manager {

	private static final Log LOG = LogFactory.getLog(Facturae31ManagerExt.class);

	private static final II18nManager I18N = I18nFactory.getI18nManager(ConstantsFacturaePolicy.LIB_NAME);
	
	
	/**
	 * Se hace lo mismo que en los constructores de las clases padre, pero cargando un trustAbstract distinto (keystore)
	 * 
	 * @throws InstantiationException
	 */
	public Facturae31ManagerExt() throws InstantiationException {
		
		LOG.info("cargando Facturae31ManagerExt");

		// Carga el validador de emisores de certificados (keystore)
		try {
			InputStream is = Facturae31ManagerExt.class.getResourceAsStream("/trust/facturae/trusted.jks");
			
			KeyStore ks = KeystoreUtil.loadKeystorePreferences(is, "sinadura");
		
			truster = new KeystoreTruster(ks);
			
		}  catch (KeyStoreException e) {
			LOG.error(e);
			throw new InstantiationException(I18N.getLocalMessage(ConstantsFacturaePolicy.I18N_POLICY_FACTURAE_30));
		} catch (NoSuchAlgorithmException e) {
			LOG.error(e);
			throw new InstantiationException(I18N.getLocalMessage(ConstantsFacturaePolicy.I18N_POLICY_FACTURAE_30));
		} catch (CertificateException e) {
			LOG.error(e);
			throw new InstantiationException(I18N.getLocalMessage(ConstantsFacturaePolicy.I18N_POLICY_FACTURAE_30));
		} catch (IOException e) {
			LOG.error(e);
			throw new InstantiationException(I18N.getLocalMessage(ConstantsFacturaePolicy.I18N_POLICY_FACTURAE_30));
		}

		// mismas comprobaciones que en los constructores padre
		if (truster == null) {
			throw new InstantiationException(I18N.getLocalMessage(ConstantsFacturaePolicy.I18N_POLICY_FACTURAE_30));
		}

		if (getConfig() == null) {
			throw new InstantiationException(I18N.getLocalMessage(ConstantsFacturaePolicy.I18N_POLICY_FACTURAE_8));
		}
	}
	
	

}
