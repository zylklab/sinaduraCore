package net.esle.sinadura.core.validate;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import net.esle.sinadura.core.certificate.CertificateUtil;
import net.esle.sinadura.core.exceptions.ConnectionException;
import net.esle.sinadura.core.exceptions.IncompleteChainException;
import net.esle.sinadura.core.exceptions.OCSPCoreException;
import net.esle.sinadura.core.exceptions.OCSPIssuerRequiredException;
import net.esle.sinadura.core.exceptions.OCSPUnknownUrlException;
import net.esle.sinadura.core.exceptions.RevokedException;
import net.esle.sinadura.core.model.ChainInfo;
import net.esle.sinadura.core.model.Status;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.tsp.TimeStampToken;


public class CertPathUtil {
	
	private static final Log log = LogFactory.getLog(CertPathUtil.class);
	

	/**
	 * All the chain ordered with the user's certificate first and the root certificate authority last.
	 * This function don't validate the input cert chain (originalChain).
	 * 
	 * @param originalChain
	 * @param certStores
	 * @return
	 * @throws CertStoreException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static CertPath completeChain(CertPath certPath, Set<CertStore> certStores)
			throws CertStoreException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException {

		
		List<X509Certificate> newChainList = new ArrayList<X509Certificate>();
		
		List<X509Certificate> originalChainList = (List<X509Certificate>)certPath.getCertificates();
		for (X509Certificate x509Certificate : originalChainList) {
			newChainList.add(x509Certificate);
		}
		
		X509Certificate lastCert = newChainList.get(newChainList.size() - 1);
		
		while (!CertificateUtil.isCA(lastCert)) {
		
			boolean find = false;
			for (CertStore certStore : certStores) {
				X509CertSelector s = new X509CertSelector();
				Collection<X509Certificate> certs = (Collection<X509Certificate>)certStore.getCertificates(s);
				for (X509Certificate cert : certs) {
					try {
						lastCert.verify(cert.getPublicKey());
						lastCert = cert;
						newChainList.add(cert);
						find = true;
						break;
					} catch (SignatureException e) {
//						logger.log(Level.INFO, "controled exception", e);
					} catch (InvalidKeyException e) {
//						logger.log(Level.INFO, "controled exception", e);
					}
				}
				if (find) {
					break;
				}
			}
			
			// borrar esto
			if (!find) {
				log.warn("Incomplete chain");
				break;
			}
		}
		
		return convert2CertPath(newChainList);
	}
	
	
	public static void isCompleteCertPath(CertPath certPath) throws IncompleteChainException {
		
		List<X509Certificate> list = (List<X509Certificate>)certPath.getCertificates();
		X509Certificate ca = list.get(list.size()-1);
		if (!CertificateUtil.isCA(ca)) {
			throw new IncompleteChainException();
		}
	}
	
    /**
     * Original by itext. Modified to return the signer certificate.
     * 
     * Verifies an OCSP response against a KeyStore.
     * 
     * @param ocsp the OCSP response
     * @param keystore the <CODE>KeyStore</CODE>
     * @param provider the provider or <CODE>null</CODE> to use the BouncyCastle provider
     * @return <CODE>true</CODE> is a certificate was found
     * @since	2.1.6
     */    
    public static X509Certificate verifyOcspCertificates(BasicOCSPResp ocsp, KeyStore keystore, String provider) {
    	
//        if (provider == null)
//            provider = "BC";
        try {
            for (Enumeration aliases = keystore.aliases(); aliases.hasMoreElements();) {
                try {
                    String alias = (String)aliases.nextElement();
                    if (!keystore.isCertificateEntry(alias))
                        continue;
                    X509Certificate certStoreX509 = (X509Certificate)keystore.getCertificate(alias);
                    if (ocsp.verify(certStoreX509.getPublicKey(), provider))
                        return certStoreX509;
                }
                catch (Exception ex) {
                }
            }
        }
        catch (Exception e) {
        }
        return null;
    }
	
	
	public static ChainInfo validateChain(X509Certificate signer, KeyStore ksTrust, Set<CertStore> certStoreList, Date date,
			boolean checkRevocation) throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			KeyStoreException, CertStoreException, NoSuchProviderException {

		ChainInfo chainInfo = new ChainInfo();
		chainInfo.setStatus(Status.UNKNOWN);
		chainInfo.setDate(date);

		try {
			// 1- complete chain
			List<X509Certificate> chain = new ArrayList<X509Certificate>();
			chain.add(signer);
			CertPath certPath = convert2CertPath(chain);
			certPath = CertPathUtil.completeChain(certPath, certStoreList);
			chainInfo.setChain((List<X509Certificate>) certPath.getCertificates());

			CertPathUtil.isCompleteCertPath(certPath);

			// print
			CertPathUtil.printCertPath(certPath);

			// 2- comprobar chain
			chain = (List<X509Certificate>) certPath.getCertificates();
			X509Certificate root = chain.get(chain.size() - 1);
			Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
			TrustAnchor trustAnchor = new TrustAnchor(root, null);
			trustAnchors.add(trustAnchor);
			CertPathUtil.verifyCertificateChain(certPath, trustAnchors, date, checkRevocation);

			// 3- trust
			CertPathUtil.buildCertPath(signer, ksTrust, certStoreList);

			chainInfo.setStatus(Status.VALID);

		} catch (IncompleteChainException e) {

			chainInfo.setStatus(Status.UNKNOWN);
			chainInfo.setError(ChainInfo.Error.INCOMPLETE);

		} catch (CertPathValidatorException e) {
			
			log.error("chain validation failed", e);

			if (e.getCause() instanceof RevokedException) {
				chainInfo.setStatus(Status.INVALID);
				chainInfo.setError(ChainInfo.Error.REVOKED);
				log.error("ChainInfo | " + Status.INVALID + ". " + ChainInfo.Error.REVOKED);
				
			} else if (e.getCause() instanceof OCSPUnknownUrlException) {
				chainInfo.setStatus(Status.UNKNOWN);
				chainInfo.setError(ChainInfo.Error.REVOCATION_UNKNOWN);
				log.error("ChainInfo | " + Status.UNKNOWN + ". " + ChainInfo.Error.REVOCATION_UNKNOWN);
				
			} else if (e.getCause() instanceof OCSPIssuerRequiredException) {
				chainInfo.setStatus(Status.UNKNOWN);
				chainInfo.setError(ChainInfo.Error.REVOCATION_UNKNOWN);
				log.error("ChainInfo | " + Status.UNKNOWN + ". " + ChainInfo.Error.REVOCATION_UNKNOWN);
				
			} else if (e.getCause() instanceof OCSPCoreException) {
				chainInfo.setStatus(Status.UNKNOWN);
				chainInfo.setError(ChainInfo.Error.REVOCATION_UNKNOWN);
				log.error("ChainInfo | " + Status.UNKNOWN + ". " + ChainInfo.Error.REVOCATION_UNKNOWN);
				
			} else if (e.getCause() instanceof ConnectionException) {
				chainInfo.setStatus(Status.UNKNOWN);
				chainInfo.setError(ChainInfo.Error.REVOCATION_UNKNOWN);
				log.error("ChainInfo | " + Status.UNKNOWN + ". " + ChainInfo.Error.REVOCATION_UNKNOWN);
				
			} else if (e.getCause() instanceof CertificateExpiredException) {
				chainInfo.setStatus(Status.INVALID);
				chainInfo.setError(ChainInfo.Error.EXPIRED);
				log.error("ChainInfo | " + Status.INVALID + ". " + ChainInfo.Error.EXPIRED);
				
			} else if (e.getCause() instanceof CertificateNotYetValidException) {
				chainInfo.setStatus(Status.INVALID);
				chainInfo.setError(ChainInfo.Error.NOTYETVALID);
				log.error("ChainInfo | " + Status.INVALID + ". " + ChainInfo.Error.NOTYETVALID);
				
			} else { // errores propios del validador de sun
				chainInfo.setStatus(Status.INVALID);
				chainInfo.setError(ChainInfo.Error.GENERIC);
				chainInfo.setLog(e.getMessage());
				log.error("ChainInfo | " + Status.INVALID + ". " + ChainInfo.Error.GENERIC);
			}
			chainInfo.setIndex(e.getIndex());

		} catch (CertPathBuilderException e) {
			chainInfo.setStatus(Status.VALID_WARNING);
			chainInfo.setError(ChainInfo.Error.UNTRUST);
			log.error("ChainInfo | " + Status.VALID_WARNING + ". " + ChainInfo.Error.UNTRUST);
			
		}

		return chainInfo;
	}
    

	public static void verifyCertificateChain(CertPath certPath, Set<TrustAnchor> trustAnchors, Date date, boolean checkRevocation)
			throws CertPathValidatorException, CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			KeyStoreException {

    	// pasar los cert del certPath a certificados creados con el provider de sun, sino da error
    	CertificateFactory certFact = CertificateFactory.getInstance("X.509");
		
    	List<Certificate> certList = (List<Certificate>) certPath.getCertificates();
    	
    	List<Certificate> newList = new ArrayList<Certificate>();
    	 
    	for (Certificate cert : certList) {

			ByteArrayInputStream bais = new ByteArrayInputStream(cert.getEncoded());
			Certificate certificate = certFact.generateCertificate(bais);
			newList.add(certificate);
		}
    	
    	CertPath certPathSun = certFact.generateCertPath(newList);
		
		// TODO si no registrarlo
		Provider provider = Security.getProvider("SUN");
    	
		// Create the parameters for the validator
		PKIXParameters params = new PKIXParameters(trustAnchors);
		params.setRevocationEnabled(false);
		
		if (checkRevocation) {
			try {
				String ocspUrl = CertificateUtil.getOCSPURL((X509Certificate)certPathSun.getCertificates().get(0));
				params.addCertPathChecker(new RevocationChecker(certPathSun, ocspUrl, date));
			} catch (OCSPUnknownUrlException e) {
				throw new CertPathValidatorException(e);
			}
		}
		
		ClassLoader loader = ClassLoader.getSystemClassLoader();
		log.info("Class loader system: " + loader.toString());
		
		log.info("Class loader sun: start");
		if (params.getClass().getClassLoader() != null) {
			log.info("Class loader sun: " + params.getClass().getClassLoader().toString());
		}
		log.info("Class loader sun: end");
		
		log.info("chain validation date: " + date.toGMTString());
		params.setDate(date);
		
//		critical policy qualifiers present in certificate
		params.setPolicyQualifiersRejected(false);
		
		// Create the validator and validate the path
		CertPathValidator certPathValidator = certPathValidator = CertPathValidator.getInstance("PKIX", provider);


		log.info("Starting path validation...");
			
		CertPathValidatorResult result = certPathValidator.validate(certPathSun, params);

		// Get the CA used to validate this path
		PKIXCertPathValidatorResult pkixResult = (PKIXCertPathValidatorResult) result;
    	
    }
    
	
	// UTILS
	
	public static CertPath convert2CertPath(Certificate[] certs) throws CertificateException {

		CertificateFactory certFact = CertificateFactory.getInstance("X.509");
		CertPath path = certFact.generateCertPath(Arrays.asList(certs));
		return path;
	}
	
    public static CertPath convert2CertPath(List certs) throws CertificateException {
    
        CertificateFactory certFact = CertificateFactory.getInstance("X.509");
        CertPath path = certFact.generateCertPath(certs);
        return path;        
    }
    
    
	public static CertStore convert2CertStore(KeyStore ks) throws KeyStoreException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException {

    	List<Certificate> mylist = new ArrayList<Certificate>();
		Enumeration<String> aliases = ks.aliases();
	    while (aliases.hasMoreElements()) {
	    	String alias = aliases.nextElement();
	    	Certificate cert = ks.getCertificate(alias);
	    	mylist.add(cert);
		}
    	CertStoreParameters cparam = new CollectionCertStoreParameters(mylist);
	    CertStore cs = CertStore.getInstance("Collection", cparam);
	    return cs;
	}
	
	public static Set<TrustAnchor> convert2TrustAnchor(KeyStore ks) throws KeyStoreException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException {
		
		Set<TrustAnchor> set = new HashSet<TrustAnchor>();
		Enumeration<String> aliases = ks.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			X509Certificate cert = (X509Certificate)ks.getCertificate(alias);
			set.add(new TrustAnchor(cert, null));
		}		
		return set;
	}
	
    
    public static CertStore convert2CertStore(CertPath certPath) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		
		List<X509Certificate> list = (List<X509Certificate>)certPath.getCertificates();
		CertStoreParameters cparam = new CollectionCertStoreParameters(list);
	    CertStore cs = CertStore.getInstance("Collection", cparam);
	    return cs;
	}
	
	
    /**
     * Devuelve un CertPath vacio en caso de que se confie directamente en el firmante
     * 
     * @param cert
     * @param ksTrust
     * @param certStoreList
     * @return
     * @throws CertPathBuilderException
     * @throws CertificateException 
     * @throws KeyStoreException 
     * @throws CertStoreException 
     */
	public static CertPath buildCertPath(X509Certificate cert, KeyStore ksTrust, Set<CertStore> certStoreList)
			throws CertPathBuilderException, CertificateException, KeyStoreException, CertStoreException {
		
		CertificateFactory certFact = CertificateFactory.getInstance("X.509");
    	List<X509Certificate> certPathList = new ArrayList<X509Certificate>();
    	X509Certificate currentCert = cert;

    	while (currentCert != null) {
    	
    		// 	comprobar si el firmante esta en el trusted
			Enumeration<String> en = ksTrust.aliases();
		
			while (en.hasMoreElements()) {
				
				X509Certificate ca = (X509Certificate)ksTrust.getCertificate(en.nextElement());
				
				if ( currentCert.getSubjectX500Principal().getName().equals(ca.getSubjectX500Principal().getName()) ) {
					
					// devuelvo un cert path vacio ya que directamente confia en el firmante
					CertPath certPath = certFact.generateCertPath(certPathList);
					return certPath;
				}
				if (currentCert.getIssuerX500Principal().getName().equals(ca.getSubjectX500Principal().getName())) {

					certPathList.add(currentCert);
					CertPath certPath = certFact.generateCertPath(certPathList);
					return certPath;
				}
			}
			
			certPathList.add(currentCert);
			
			X509CertSelector s = new X509CertSelector();
			s.setSubject(((X509Certificate)currentCert).getIssuerX500Principal());
				
			// recorro los certStore
			Iterator<CertStore> it = certStoreList.iterator();
			boolean find = false;
				
			while (it.hasNext() && !find ) {
					
				CertStore certStore = it.next();
				Collection<X509Certificate> set = (Collection<X509Certificate>)certStore.getCertificates(s);
				
				if (set.size() > 0) { // encontrado el CA
					
					X509Certificate nextCert = (X509Certificate)set.iterator().next();
					// Si no es el root CA
					if (!nextCert.getSubjectX500Principal().getName().equals(nextCert.getIssuerX500Principal().getName())) {
						
						currentCert = nextCert;							
						find = true;
						
					} else {
						currentCert = null;
					}
				}	
			}
			
			if (!find) { // si no lo ha encontrado 
				
				currentCert = null;
			}
		}
		
    	throw new CertPathBuilderException("no se ha podido completar la chain");
		
    }
    
    // no se usa.
	public static CertPath buildCertPathSun(X509Certificate cert, KeyStore ksTrust, List<CertStore> certStoreList)
			throws CertPathBuilderException {

		X509CertSelector s = new X509CertSelector();
		
		s.setSerialNumber(((X509Certificate)cert).getSerialNumber());
		try {
			s.setSubject(((X509Certificate)cert).getSubjectX500Principal().getEncoded());
			log.info("Builder: " + cert.getSubjectX500Principal().getName());
		} catch (IOException e) {
			log.error("", e);
		}

		PKIXBuilderParameters parameters = null;
		try {
//	    		parameters = new PKIXBuilderParameters( Collections.singleton(new TrustAnchor((X509Certificate)cert, null)), s);
			parameters = new PKIXBuilderParameters(ksTrust, s);
			
		} catch (KeyStoreException e) {
			log.error("", e);
		} catch (InvalidAlgorithmParameterException e) {
			log.error("", e);
		}
		
		parameters.setRevocationEnabled(false);

		for (CertStore certStore : certStoreList) {
			
			parameters.addCertStore(certStore);
		}
		
		CertPathBuilder certPathBuilder = null;
		try {
			certPathBuilder = CertPathBuilder.getInstance("PKIX");
		} catch (NoSuchAlgorithmException e) {
			log.error("", e);
		}
		
		PKIXCertPathBuilderResult r = null;
		try {
			r = (PKIXCertPathBuilderResult)certPathBuilder.build(parameters);
		} catch (InvalidAlgorithmParameterException e) {
			log.error("", e);
		}
		
		CertPath cp = r.getCertPath();
		log.info("size: " + cp.getCertificates().size());
		
		for (Certificate c : cp.getCertificates()) {
			
			log.info("chain: " + ((X509Certificate)c).getSubjectDN());	
		}
		
		TrustAnchor anchor = r.getTrustAnchor();
		log.info("trust: " + anchor.getTrustedCert().getSubjectDN());
		
		return cp;
    }


	public static void printCertPath(CertPath certPath) {
		
		List<X509Certificate> list = (List<X509Certificate>)certPath.getCertificates();
		log.info("---print cert path---");
		for (X509Certificate certificate : list) {
			log.info("certificate.getSubjectDN(): " + certificate.getSubjectDN());
		}		
	}
	

}
