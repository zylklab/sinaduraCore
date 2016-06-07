//package net.esle.sinadura.core.crl;
//
//import java.io.FileInputStream;
//import java.io.FileNotFoundException;
//import java.security.cert.CRL;
//import java.security.cert.CRLException;
//import java.security.cert.CertificateException;
//import java.security.cert.CertificateFactory;
//import java.util.logging.Level;
//import java.util.logging.Logger;
//
//import net.esle.sinadura.core.exceptions.CoreCRLException;
//
//
//import sun.security.x509.X509CertImpl;
//
//public class CRLChecker {
//	
//	private static final Logger logger = Logger.getLogger("net.facturae.core.crl.CRLChecker");
//	public static final int CERT_STATUS_GOOD = 0;
//	public static final int CERT_STATUS_REVOKED = 1;
//	public static final int CERT_STATUS_UNKNOWN = 2;
//	
//	public static int check(X509CertImpl certificado, String crlFile) throws CoreCRLException
//	{
//		CRL crl  = null;
//		try {
//			crl  = CertificateFactory.getInstance("X.509").generateCRL(new FileInputStream(crlFile));
//		} catch (CRLException e) {
//			logger.log(Level.SEVERE,"CRLException",e);
//			throw new CoreCRLException(e);
//		} catch (CertificateException e) {
//			logger.log(Level.SEVERE,"CertificateException",e);
//			throw new CoreCRLException(e);
//		} catch (FileNotFoundException e) {
//			logger.log(Level.SEVERE,"FileNotFoundException",e);
//			throw new CoreCRLException(e);
//		}
//		if(crl == null)
//		{
//			return CERT_STATUS_UNKNOWN;
//		}
//		else
//		{
//			boolean isrevoked =  crl.isRevoked(certificado);
//			if(isrevoked)
//			{
//				return CERT_STATUS_REVOKED;
//			}
//			else
//			{
//				return CERT_STATUS_GOOD;
//			}
//		}
//	}
//}
