package net.esle.sinadura.core.certificate;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import net.esle.sinadura.core.exceptions.OCSPUnknownUrlException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;

public class CertificateUtil {

	private static Log log = LogFactory.getLog(CertificateUtil.class);
	
	public static boolean isCA(X509Certificate cert) {
		
		// realmente creo que hay que comprobar que esta firmado por uno mismo
		if (cert.getIssuerX500Principal().getName(X500Principal.RFC2253).equals(
				cert.getSubjectX500Principal().getName(X500Principal.RFC2253))) {
			return true;
		} else {
			return false;
		}	
	}
	
	public static String getFormattedName(X509Certificate cert) {
		
		try {
			X509Principal principal = new X509Principal(cert.getSubjectX500Principal().getEncoded());
			Vector<String> cn = principal.getValues(X509Principal.CN);
			String s = "";
			
	        if (cn != null && cn.size() > 0) {
	        	s += cn.get(0) + "";
	        }
	        	
	        if(s == null || s.equals("")) {
	        	cn = principal.getValues(X509Principal.O);
		        if (cn != null && cn.size() > 0)
		        	s += cn.get(0) + "";
	        }
			
			return s;
			
		} catch (IOException e) {

			return "N/A";
		}
	}
	
	
	public static String getKeyUsage(X509Certificate cert) {
		
		String s = "";
		
		// key usage
		boolean[] usage = cert.getKeyUsage();
		
		List<String> extended = null;
		try {
			extended = cert.getExtendedKeyUsage();
		} catch (CertificateParsingException e) {
			log.error("", e);
		}
		
		if (usage != null){
			
			for (int j = 0 ; j< usage.length; j++) {
				
				if (j == 0 && usage[j]) 
					s += "Digital signature, ";
				if (j == 1 && usage[j]) 			// non-repudiation o contentCommitmentrenombrado posteriorment a contentCommitment
					s += "Non repudiation, ";
				if (j == 2 && usage[j]) 
					s += "Key encipherment, ";
				if (j == 3 && usage[j]) 
					s += "Data encipherment, ";
				if (j == 4 && usage[j]) 
					s += "Key agreement, ";
				if (j == 5 && usage[j]) 
					s += "KeyCert sign, ";
				if (j == 6 && usage[j]) 
					s += "CRL sign, ";
				if (j == 7 && usage[j]) 
					s += "Encipher only, ";
				if (j == 8 && usage[j]) 
					s += "Decipher only, ";
			}
		}
		
		if (extended != null){
			for (String ext : extended) {
				if (ext.equals("1.3.6.1.5.5.7.3.1"))
					s += "Server authentication, " ;
				if (ext.equals("1.3.6.1.5.5.7.3.2"))
					s += "Client authentication, " ;
				if (ext.equals("1.3.6.1.5.5.7.3.3"))
					s += "Code signing, " ;
				if (ext.equals("1.3.6.1.5.5.7.3.4"))
					s += "E-mail protection, " ;
				if (ext.equals("1.3.6.1.5.5.7.3.5"))
					s += "IP security end system, " ;
				if (ext.equals("1.3.6.1.5.5.7.3.6"))
					s += "IP security tunnel termination, " ;
				if (ext.equals("1.3.6.1.5.5.7.3.7"))
					s += "IP security user, " ;
				if (ext.equals("1.3.6.1.5.5.7.3.8"))
					s += "Timestamping, " ;
				if (ext.equals("1.3.6.1.5.5.7.3.9"))
					s += "OCSP signing, " ;
			}
		}
		return s;
	}
	
	public static boolean esNonRepudiation(X509Certificate cert){
		String usage = getKeyUsage(cert);
		if (usage != null && usage.trim().length() > 0){
			return usage.toLowerCase().contains("non repudiation");
		}else{
			return true;
		}
	}

	public static boolean esDigitalSignature(X509Certificate cert){
		String usage = getKeyUsage(cert);
		if (usage != null && usage.trim().length() > 0){
			return usage.toLowerCase().contains("digital signature");
		}else{
			return true;
		}
	}
	
	public static boolean keyUsageNoDefinido(X509Certificate cert){
		String usage = getKeyUsage(cert);
		if (usage != null && usage.trim().length() == 0){
			return true;
		}else{
			return false;
		}
	}
	
	
	/**
	 * Get a unique id from a certificate ( certificate.getSubjectX500Principal().getName() + certificate.getSerialNumber() )
	 * 
	 * @param cert
	 * @return the id
	 */
	public static String getUniqueID(X509Certificate cert) {
		
		return (cert.getSubjectX500Principal().getName() + cert.getSerialNumber());		
	}
	
	
	public static String getOCSPURL(X509Certificate certificate) throws OCSPUnknownUrlException {

//		return "http://ocsp.wisekey.com";
		
		try {
			DERObject obj = getExtensionValue(certificate, X509Extensions.AuthorityInfoAccess.getId());
			if (obj == null) {
				throw new OCSPUnknownUrlException();
			}

			ASN1Sequence AccessDescriptions = (ASN1Sequence) obj;
			for (int i = 0; i < AccessDescriptions.size(); i++) {
				ASN1Sequence AccessDescription = (ASN1Sequence) AccessDescriptions.getObjectAt(i);
				if (AccessDescription.size() != 2) {
					continue;
				} else {
					if (AccessDescription.getObjectAt(0) instanceof DERObjectIdentifier
							&& ((DERObjectIdentifier) AccessDescription.getObjectAt(0)).getId().equals("1.3.6.1.5.5.7.48.1")) {
						String AccessLocation = getStringFromGeneralName((DERObject) AccessDescription.getObjectAt(1));
						if (AccessLocation == null) {
							throw new OCSPUnknownUrlException();
						} else {
							return AccessLocation;
						}
					}
				}
			}
			
			throw new OCSPUnknownUrlException();
			
		} catch (IOException e) {
			throw new OCSPUnknownUrlException();
		}
	}
	
	private static DERObject getExtensionValue(X509Certificate cert, String oid) throws IOException {
		
        byte[] bytes = cert.getExtensionValue(oid);
        if (bytes == null) {
            return null;
        }
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        return aIn.readObject();
    }
	
	private static String getStringFromGeneralName(DERObject names) throws IOException {
		
        DERTaggedObject taggedObject = (DERTaggedObject) names ;
        return new String(ASN1OctetString.getInstance(taggedObject, false).getOctets(), "ISO-8859-1");
    }

}
