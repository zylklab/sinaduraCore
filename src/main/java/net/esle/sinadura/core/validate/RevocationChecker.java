package net.esle.sinadura.core.validate;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import net.esle.sinadura.core.exceptions.ConnectionException;
import net.esle.sinadura.core.exceptions.OCSPCoreException;
import net.esle.sinadura.core.exceptions.OCSPIssuerRequiredException;
import net.esle.sinadura.core.exceptions.RevokedException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * De momento unicamente soporta validacion de ocsp en tiempo real.
 * 
 * Mejoras adicionales: 
 * 1- Recibir respuestas ocsp de origen externo (se le pasarian en el contructor).
 * 2- CRL (lo mismo, en tiempo real o como datos externos)
 * 
 * @author alfredo
 * 
 */
class RevocationChecker extends PKIXCertPathChecker {
	
	private static Log log = LogFactory.getLog(RevocationChecker.class);

	private CertPath certPath;
	private String ocspUrl;
	private Date date;

	
	public RevocationChecker(CertPath certPath, String ocspUrl, Date date) {
		this.certPath = certPath;
		this.ocspUrl = ocspUrl;
		this.date = date;
	}

	@Override
	public void init(boolean forwardChecking) throws CertPathValidatorException {
		// ignore
	}
	
	@Override
	public boolean isForwardCheckingSupported() {
		return true;
	}

	@Override
	public Set getSupportedExtensions() {
		return null;
	}
	
	@Override
	public void check(Certificate cert, Collection extensions) throws CertPathValidatorException {
		
		log.info("pasando por el RevocationChecker");
		
		X509Certificate certificate = (X509Certificate)cert;
		
		// si no es CA // TODO pasar esta comprobacion a una funcion
		if (!certificate.getIssuerX500Principal().getName(X500Principal.RFC2253).equals(
				certificate.getSubjectX500Principal().getName(X500Principal.RFC2253))) {
		
			try {
				CertStore certStore = CertPathUtil.convert2CertStore(certPath);
				X509CertSelector s = new X509CertSelector();
				s.setSubject(certificate.getIssuerX500Principal());
				Set<X509Certificate> set = (Set<X509Certificate>)certStore.getCertificates(s);
				
				if (set != null && set.size() > 0) {			
					X509Certificate issuer = set.iterator().next();
					OcspUtil.getStatus(certificate, issuer, ocspUrl, date);
				} else {
					throw new OCSPIssuerRequiredException();
				}
	
			} catch (RevokedException e) {
				 throw new CertPathValidatorException(e);
			} catch (OCSPCoreException e) {
				throw new CertPathValidatorException(e);
			} catch (OCSPIssuerRequiredException e) {
				throw new CertPathValidatorException(e);
			} catch (InvalidAlgorithmParameterException e) {
				throw new CertPathValidatorException(e);
			} catch (NoSuchAlgorithmException e) {
				throw new CertPathValidatorException(e);
			} catch (CertStoreException e) {
				throw new CertPathValidatorException(e);
			} catch (ConnectionException e) {
				throw new CertPathValidatorException(e);
			}
		}
	}
}


