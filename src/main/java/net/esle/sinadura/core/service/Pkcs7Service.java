package net.esle.sinadura.core.service;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import net.esle.sinadura.core.exceptions.Pkcs7Exception;
import net.esle.sinadura.core.exceptions.ValidationInterruptedException;
import net.esle.sinadura.core.model.ChainInfo;
import net.esle.sinadura.core.model.PDFSignatureInfo;
import net.esle.sinadura.core.model.Status;
import net.esle.sinadura.core.model.ValidationError;
import net.esle.sinadura.core.validate.CertPathUtil;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;


public class Pkcs7Service {
	
	private static Log log = LogFactory.getLog(Pkcs7Service.class);
	
	
	public static byte[] getSignedContent(byte[] sigbytes) throws Pkcs7Exception {
		
		try {
			CMSSignedData s = new CMSSignedData(sigbytes);
			CMSProcessableByteArray cpb = (CMSProcessableByteArray) s.getSignedContent();
			byte[] content = (byte[]) cpb.getContent();
			
			return content;
			
		} catch (CMSException e) {
			throw new Pkcs7Exception(e);
		}
	}
	
	
	public static List<PDFSignatureInfo> validate(byte[] sigbytes, KeyStore ksCache, KeyStore ksTrust) throws Pkcs7Exception {
		
		// esta sentencia ya indica que el fichero a pasado el proceso de validacion
		List<PDFSignatureInfo> pdfSignaturesList = new ArrayList<PDFSignatureInfo>();
		
		try {
			Security.addProvider(new BouncyCastleProvider());
			
			CMSSignedData signature = new CMSSignedData(sigbytes);
			CertStore certStore = signature.getCertificatesAndCRLs("Collection", "BC");
			Set<CertStore> certStores = new HashSet<CertStore>();
			certStores.add(certStore);
			certStores.add(CertPathUtil.convert2CertStore(ksCache));
			
			SignerInformationStore store = signature.getSignerInfos();
			Collection<SignerInformation> signers = store.getSigners();
			for (SignerInformation signerInform : signers) {
				PDFSignatureInfo pdfSignature = validateSigner(signerInform, certStores, ksTrust);
				pdfSignaturesList.add(pdfSignature);
			}
			
			return pdfSignaturesList;
			
		} catch (CMSException e) {
			throw new Pkcs7Exception(e);
		} catch (IOException e) {
			throw new Pkcs7Exception(e);
		} catch (NoSuchAlgorithmException e) {
			throw new Pkcs7Exception(e);
		} catch (NoSuchProviderException e) {
			throw new Pkcs7Exception(e);
		} catch (CertificateException e) {
			throw new Pkcs7Exception(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new Pkcs7Exception(e);
		} catch (KeyStoreException e) {
			throw new Pkcs7Exception(e);
		} catch (CertStoreException e) {
			throw new Pkcs7Exception(e);
		} catch (TSPException e) {
			throw new Pkcs7Exception(e);
		}

	}
	
	
	private static Date getSignatureTime(SignerInformation signer) {
		
		AttributeTable atab = signer.getSignedAttributes();
		Date result = null;
		if (atab != null) {
			Attribute attr = atab.get(CMSAttributes.signingTime);
			if (attr != null) {
				Time t = Time.getInstance(attr.getAttrValues().getObjectAt(0).getDERObject());
				result = t.getDate();
			}
		}
		return result;
	}

	
	private static PDFSignatureInfo validateSigner(SignerInformation signerInform, Set<CertStore> certStores, KeyStore ksTrust)
			throws CMSException, IOException, CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			KeyStoreException, CertStoreException, NoSuchProviderException, TSPException {
		
		PDFSignatureInfo pdfSignature = new PDFSignatureInfo(); 
		pdfSignature.setStatus(Status.UNKNOWN);
		
		try {
			
			// buscar signer
			X509Certificate signer = null;
			for (CertStore certStore : certStores) {
				Collection<X509Certificate> certCollection = (Collection<X509Certificate>) certStore.getCertificates(signerInform.getSID());
				if (certCollection != null && !certCollection.isEmpty()) {
					signer = certCollection.iterator().next();
				}
			}

			// verificar
			if (!signerInform.verify(signer.getPublicKey(), "BC")) {

				pdfSignature.setError(ValidationError.CORRUPT);
				pdfSignature.setStatus(Status.INVALID);
				throw new ValidationInterruptedException();
			}
			
			
			// STANDARD DATE
			Date date = getSignatureTime(signerInform);
			if (date == null) {
				// si no tiene fecha seteo la de inicio del certificado
				date = signer.getNotBefore();
			}
			pdfSignature.setDate(date);
			
			
			// TIMESTAMP
			TimeStampToken token = null;
			AttributeTable attrs = signerInform.getUnsignedAttributes();
			if (attrs != null) {
				Attribute attribute = attrs.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
				if (attribute != null) {
					DEREncodable dob = attribute.getAttrValues().getObjectAt(0);
					CMSSignedData signedData = new CMSSignedData(dob.getDERObject().getEncoded());
					token = new TimeStampToken(signedData);
				}
			}
			
//			if (token != null) {
//				TimestampInfo timestampInfo = validateTimestamp(token, pk, ksCache, ksTrust);
//				pdfSignature.setTimestampInfo(timestampInfo);
//				if (timestampInfo.getStatus().equals(Status.VALID)) {
//					pdfSignature.setDate(timestampInfo.getDate());
//				} else {
//					// si el time stamp es invalido pongo la firma a warning
//					pdfSignature.setStatus(Status.VALID_WARNING);
//				}
//			} else {
				// sin timestamp (hora local)
				pdfSignature.setStatus(Status.VALID_WARNING);
//			}
			
			

			// BUILD AND VALIDATE THE CHAIN
			ChainInfo chainInfo = CertPathUtil.validateChain(signer, ksTrust, certStores, pdfSignature.getDate(), true);
			pdfSignature.setChainInfo(chainInfo);
			
			if (!chainInfo.getStatus().equals(Status.VALID)) {
				pdfSignature.setStatus(chainInfo.getStatus()); // valid_warning o unknown
				pdfSignature.setError(ValidationError.CHAIN_ERROR);
				throw new ValidationInterruptedException();				
			}
			
			// si esta a valid_warning por lo del ts no se le sube el nivel a valido
			if (!pdfSignature.getStatus().equals(Status.VALID_WARNING)) {
				pdfSignature.setStatus(Status.VALID);
			}
			
			
		} catch (ValidationInterruptedException e) {
			log.info("proceso de validacion interrumpido, resultado no valido");
		}
		
		return pdfSignature;
		
	}
	
	
	
}
