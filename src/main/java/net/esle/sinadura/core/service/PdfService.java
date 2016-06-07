package net.esle.sinadura.core.service;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import net.esle.sinadura.core.certificate.CertificateUtil;
import net.esle.sinadura.core.exceptions.ConnectionException;
import net.esle.sinadura.core.exceptions.OCSPCoreException;
import net.esle.sinadura.core.exceptions.OCSPIssuerRequiredException;
import net.esle.sinadura.core.exceptions.OCSPUnknownUrlException;
import net.esle.sinadura.core.exceptions.PdfSignatureException;
import net.esle.sinadura.core.exceptions.RevokedException;
import net.esle.sinadura.core.exceptions.TsValidationInterruptedException;
import net.esle.sinadura.core.exceptions.ValidationFatalException;
import net.esle.sinadura.core.exceptions.ValidationInterruptedException;
import net.esle.sinadura.core.model.ChainInfo;
import net.esle.sinadura.core.model.PDFSignatureInfo;
import net.esle.sinadura.core.model.PdfSignaturePreferences;
import net.esle.sinadura.core.model.Status;
import net.esle.sinadura.core.model.TimestampInfo;
import net.esle.sinadura.core.model.ValidationError;
import net.esle.sinadura.core.util.FileUtil;
import net.esle.sinadura.core.util.PropertiesCoreUtil;
import net.esle.sinadura.core.validate.CertPathUtil;
import net.esle.sinadura.core.validate.OcspUtil;
import net.esle.sinadura.core.validate.TimestampUtil;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.ExceptionConverter;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.exceptions.BadPasswordException;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.AcroFields.Item;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfPKCS7;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.TSAClient;
import com.itextpdf.text.pdf.TSAClientBouncyCastle;

public class PdfService {

	private static Log log = LogFactory.getLog(PdfService.class);

	
	/**
	 * 
	 * Si se va a escribir a un fichero (en fileSystem) utilizar este metodo, ya que no tiene problemas de memoria.
	 * 
	 * @param is
	 * @param outputPath
	 * @param signaturePreferences
	 * @param pwdProtection
	 * @throws PdfSignatureException
	 * @throws OCSPCoreException
	 * @throws RevokedException
	 * @throws ConnectionException
	 * @throws OCSPIssuerRequiredException
	 * @throws OCSPUnknownUrlException
	 * @throws CertificateExpiredException
	 * @throws CertificateNotYetValidException
	 * @throws BadPasswordException
	 */
	public static void sign(String inputPath, String outputPath, PdfSignaturePreferences signaturePreferences, PasswordProtection pwdProtection)
			throws PdfSignatureException, OCSPCoreException, RevokedException, ConnectionException, OCSPIssuerRequiredException,
			OCSPUnknownUrlException, CertificateExpiredException, CertificateNotYetValidException, BadPasswordException {
		
		sign(null, inputPath, null, outputPath, signaturePreferences, pwdProtection);
	}
	
	/**
	 * 
	 * Este metodo puede llegar a dar un outofmemory con documentos grandes si no hay memoria suficiente.
	 * 
	 * @param is
	 * @param os
	 * @param signaturePreferences
	 * @param pwdProtection
	 * @throws PdfSignatureException
	 * @throws OCSPCoreException
	 * @throws RevokedException
	 * @throws ConnectionException
	 * @throws OCSPIssuerRequiredException
	 * @throws OCSPUnknownUrlException
	 * @throws CertificateExpiredException
	 * @throws CertificateNotYetValidException
	 * @throws BadPasswordException
	 */
	public static void sign(InputStream is, OutputStream os, PdfSignaturePreferences signaturePreferences, PasswordProtection pwdProtection)
			throws PdfSignatureException, OCSPCoreException, RevokedException, ConnectionException, OCSPIssuerRequiredException,
			OCSPUnknownUrlException, CertificateExpiredException, CertificateNotYetValidException, BadPasswordException {
		
		sign(is, null, os, null, signaturePreferences, pwdProtection);
	}
	
	
	private static void sign(InputStream is, String inputPath, OutputStream os, String outputPath, PdfSignaturePreferences signaturePreferences, PasswordProtection pwdProtection)
			throws PdfSignatureException, OCSPCoreException, RevokedException, ConnectionException, OCSPIssuerRequiredException,
			OCSPUnknownUrlException, CertificateExpiredException, CertificateNotYetValidException {
		
		final String targetPath = StringUtils.trimToNull(outputPath);
		if (targetPath == null && os == null) {
			throw new IllegalArgumentException("Destination PDF path cannot be blank");
		}
		
		try {
			
			KeyStore ks = signaturePreferences.getKsSignaturePreferences().getKs();
			String alias = signaturePreferences.getKsSignaturePreferences().getAlias();
			
			// aqui no suelen estar los certificados raiz
			Certificate[] chain = ks.getCertificateChain(alias);
			
			// check certificate
			X509Certificate cert = (X509Certificate)chain[0];
			cert.checkValidity();

			KeyStore.PrivateKeyEntry keyEntry = null;
			keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, signaturePreferences.getKsSignaturePreferences().getPasswordProtection());
			PrivateKey pk = keyEntry.getPrivateKey();
			

			// completar chain
			if (signaturePreferences.getKsCache() != null) {
				
				CertPath certPath = CertPathUtil.convert2CertPath(chain);
				Set<CertStore> certStores = new HashSet<CertStore>();
				certStores.add(CertPathUtil.convert2CertStore(signaturePreferences.getKsCache()));
				certPath = CertPathUtil.completeChain(certPath, certStores);
				List<Certificate> tmpList = (List<Certificate>)certPath.getCertificates();
				chain = (Certificate[])tmpList.toArray(new Certificate[tmpList.size()]);
			}

			TSAClient tsc = null;
			if (signaturePreferences.getTimestampUrl() != null && !signaturePreferences.getTimestampUrl().equals("")) {
				tsc = new TSAClientBouncyCastle(signaturePreferences.getTimestampUrl(), signaturePreferences.getTimestampUser(),
						signaturePreferences.getTimestampPassword());
			}
			
			// pdfs protegidos
			byte[] ownerPassword = null;
			if ((pwdProtection != null) && (pwdProtection.getPassword() != null)) {
				ownerPassword = new String(pwdProtection.getPassword()).getBytes();
			}
			
			
			PdfReader reader;
			if (inputPath != null) {
				reader = new PdfReader(inputPath, ownerPassword);
				
			}else{
				reader = new PdfReader(is, ownerPassword);
			}
			
			PdfStamper stp;
			File targetFile = null;
			if(targetPath != null)
			{
				targetFile = FileUtil.getLocalFileFromURI(targetPath);
				
			}
			try {
				if(os == null && targetFile != null)
				{
					stp = PdfStamper.createSignature(reader, null, '\0', targetFile, true);
				}
				else if(os != null && targetFile == null)
				{
					stp = PdfStamper.createSignature(reader, os, '\0', null, true);
				}
				else if(os != null && targetFile != null)
				{
					stp = PdfStamper.createSignature(reader, os, '\0', targetFile, true);
				}
				else
				{
					stp = null;
					throw new IOException("outputstrema and targetFile are null");
				}
			} catch (DocumentException e) {
				targetFile.delete();
				throw e;
			} catch (IOException e) {
				targetFile.delete();
				throw e;
			}

			PdfSignatureAppearance sap = stp.getSignatureAppearance();
			
			sap.setCrypto(null, chain, null, PdfSignatureAppearance.SELF_SIGNED);

			if (signaturePreferences.getReason() != null && !signaturePreferences.getReason().equals("")) {
				sap.setReason(signaturePreferences.getReason());
			}
			if (signaturePreferences.getLocation() != null && !signaturePreferences.getLocation().equals("")) {
				sap.setLocation(signaturePreferences.getLocation());
			}


			// pagina
			int page = 1;
			if (signaturePreferences.getPage() == 0 || signaturePreferences.getPage() > reader.getNumberOfPages())	{
				page = reader.getNumberOfPages();
			} else {
				page = signaturePreferences.getPage();
			}

			// imagen
			if (signaturePreferences.getImage() != null) {
				sap.setImage(signaturePreferences.getImage());
			}

			String acroFieldName = signaturePreferences.getAcroField();			
			if (acroFieldName != null && !acroFieldName.equals("")) {
				
				log.debug("-- AcroField: " + acroFieldName);

				Item acroField = reader.getAcroFields().getFieldItem(acroFieldName);
				
				// op1. community - acrofield desde openoffice
				//----------------------------------------------
				
				// si es sign-field
				if (PdfName.SIG.equals(PdfReader.getPdfObject(acroField.getMerged(0).get(PdfName.FT)))) {
					
					log.info("acroFieldName --> SIG");
					sap.setVisibleSignature(acroFieldName);
					
				// si no es un sign-field detectamos la posicion
				} else {
					
					log.info("acroFieldName --> else");
					
					List<AcroFields.FieldPosition> positions = reader.getAcroFields().getFieldPositions(acroFieldName);
					sap.setVisibleSignature(positions.get(0).position, reader.getNumberOfPages(), null);
					
					// TODO ver si esto hace falta
					//acroFields.removeField(acroFieldName);
					
				// op2. el workaround para lantik, en base a un metadato pre-imagen
				// @irune - MyImageRenderListener esta sin subir
				//----------------------------------------------						
				// buscamos primera imagen y sustituimos
//					}else{
//						
//					       for (int i=1; i< reader.getNumberOfPages()+1; i++){
//					    	   System.out.println("number of page: " + i);
//					    	   MyImageRenderListener listener = new MyImageRenderListener(null);
//						       PdfContentStreamProcessor processor = new PdfContentStreamProcessor(listener);
//					    	   PdfDictionary pageDic = reader.getPageN(i);
//						       PdfDictionary resourcesDic = pageDic.getAsDict(PdfName.RESOURCES);
//						       processor.processContent(ContentByteUtils.getContentBytesForPage(reader, i), resourcesDic);
//						       
//								x1 = (int) listener.getX();
//								y1 = (int) listener.getY();
//								x2 = (int) (x1 + listener.getWidth());
//								y2 = (int) (y1 + listener.getHeight());
//								
//							   System.out.println(x1 + "-" + y2 + "-" + x2 + "-" + y2);
//						       sap.setVisibleSignature(new Rectangle(x1, y1, x2, y2), i, null);				    	   
//					       }
				}
				
				
				
			} else if (signaturePreferences.getVisible()) {
				
				// conversion de cordenadas itext --> awt/swt
				Rectangle pageSize = reader.getPageSize(page);
				float x1 = signaturePreferences.getStartX();
				float y1 = pageSize.getHeight() - signaturePreferences.getHeight() - signaturePreferences.getStartY();
				float x2 = x1 + signaturePreferences.getWidht();
				float y2 = y1 + signaturePreferences.getHeight();
				
				/*
				 *  TODO aqui estaria bien poder cambiar el nombre
				 *  @irune, el nombre de que? O.o
				 */
				sap.setVisibleSignature(new Rectangle(x1, y1, x2, y2), page, null);							
			}

			// Certificación del PDF
			sap.setCertificationLevel(signaturePreferences.getCertified());

			PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached"));
			dic.setReason(sap.getReason());
			dic.setLocation(sap.getLocation());
			dic.setContact(sap.getContact());
			dic.setDate(new PdfDate(sap.getSignDate()));
			sap.setCryptoDictionary(dic);

			
			int contentEstimated = Integer.valueOf(PropertiesCoreUtil.getProperty(PropertiesCoreUtil.PDF_SIGN_RESERVED_SPACE));
			log.debug("Tamanio reservado para la firma en el PDF: " + contentEstimated);
			
			HashMap exc = new HashMap();
			exc.put(PdfName.CONTENTS, new Integer(contentEstimated * 2 + 2));
			sap.preClose(exc);

			PdfPKCS7 sgn = new PdfPKCS7(pk, chain, null, "SHA1", null, false);
			InputStream data = sap.getRangeStream();
			MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
			byte buf[] = new byte[8192];
			int n;
			while ((n = data.read(buf)) > 0) {
				messageDigest.update(buf, 0, n);
			}
			byte hash[] = messageDigest.digest();
			Calendar cal = Calendar.getInstance();

			// ocsp
			byte[] ocsp = null;
			if (signaturePreferences.getAddOCSP()) {
				if (chain.length >= 2) {
					String url = CertificateUtil.getOCSPURL((X509Certificate) chain[0]);	
					ocsp = OcspUtil.getStatus((X509Certificate) chain[0], (X509Certificate) chain[1], url, new Date());
				} else {
					throw new OCSPIssuerRequiredException();
				}
			}

			byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, cal, ocsp);
			sgn.update(sh, 0, sh.length);

			byte[] encodedSig = sgn.getEncodedPKCS7(hash, cal, tsc, ocsp);

			if (contentEstimated + 2 < encodedSig.length) {
				throw new PdfSignatureException("Not enough space");
			}

			byte[] paddedSig = new byte[contentEstimated];
			System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

			PdfDictionary dic2 = new PdfDictionary();
			dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
			sap.close(dic2);


		} catch (ExceptionConverter e) { // runtime de itext
			if (e.getException() instanceof SocketException) {
				throw new ConnectionException(e.getException());
			} else {
				throw new PdfSignatureException(e.getException());
			}
		} catch (SignatureException e) {
			throw new PdfSignatureException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new PdfSignatureException(e);
		} catch (UnrecoverableEntryException e) {
			throw new PdfSignatureException(e);
		} catch (KeyStoreException e) {
			throw new PdfSignatureException(e);
		} catch (IOException e) {
			throw new PdfSignatureException(e);
		} catch (DocumentException e) {
			throw new PdfSignatureException(e);
		} catch (InvalidKeyException e) {
			throw new PdfSignatureException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new PdfSignatureException(e);
		} catch (CertStoreException e) {
			throw new PdfSignatureException(e);
		} catch (NoSuchProviderException e) {
			throw new PdfSignatureException(e);
		} catch (CertificateException e) {
			if (e instanceof CertificateExpiredException) {
				throw (CertificateExpiredException)e;
			} else if (e instanceof CertificateNotYetValidException) {
				throw (CertificateNotYetValidException)e;
			} else {
				throw new PdfSignatureException(e);
			}
		}
	}
	
	public static List<PDFSignatureInfo> validate(String path, KeyStore ksCache, KeyStore ksTrust) throws ValidationFatalException {
			try {
				
				URI fileUri = new URI(FileUtil.urlEncoder(FileUtil.normaliceLocalURI(path)));
				String readableFile = FileUtil.getLocalPathFromURI(fileUri);
						
				/*
				 * validación de fichero local (path)
				 */
				if (fileUri.getScheme() == null || fileUri.getScheme().equalsIgnoreCase("file")){
					return  validate(null,readableFile ,ksCache,ksTrust);
					
				/*
				 * validación de fichero remoto (stream)
				 */
				}else{
					return  validate(FileUtil.getInputStreamFromURI(path), null, ksCache,ksTrust);					
				}


			} catch (URISyntaxException e) {
				throw new ValidationFatalException(e);
			} catch (IOException e) {
				throw new ValidationFatalException(e);
			}
	}
	
	/**
	 * 
	 * Este metodo no se utiliza desde Sinadura Desktop, pero sí desde el servicio de valdiacion de firmas integrado en Alfresco.
	 * 
	 * @param is
	 * @param ksCache
	 * @param ksTrust
	 * @return
	 * @throws ValidationFatalException
	 */
	public static List<PDFSignatureInfo> validate(InputStream is, KeyStore ksCache, KeyStore ksTrust) throws ValidationFatalException {
		
		return validate(is, null, ksCache, ksTrust);
	}
	
	
	private static List<PDFSignatureInfo> validate(InputStream is, String filePath, KeyStore ksCache, KeyStore ksTrust) throws ValidationFatalException {

		try {
			// esta sentencia ya indica que el fichero a pasado el proceso de validacion
			List<PDFSignatureInfo> pdfSignaturesList = new ArrayList<PDFSignatureInfo>();

			// bouncycastle provider ("BC")
			// TODO pasar el provider más arriba
			Security.addProvider(new BouncyCastleProvider());

			PdfReader reader;
			if (filePath != null){
				reader = new PdfReader(filePath);
			}else{
				reader = new PdfReader(is);
			}
			
			AcroFields af = reader.getAcroFields();
			ArrayList<String> names = af.getSignatureNames();
			for (String name : names) {
				PDFSignatureInfo pdfSignature = validateSignature(name, af, ksCache, ksTrust);
				pdfSignaturesList.add(pdfSignature);
			}
			
			
			class PdfComparator implements Comparator {
				
			    public int compare(Object pdf1, Object pdf2){

			    	Date date1 = ((PDFSignatureInfo)pdf1).getDate();        
			        Date date2 = ((PDFSignatureInfo)pdf2).getDate();
			       
			        if (date1 != null && date2 != null && date1.after(date2)) {
			        	return 1;
			        } else if (date1 != null && date2 != null && date1.before(date2)) {
			        	return -1;
			        } else {
			        	return 0;
			        }     
			    }
			}
			
			Collections.sort(pdfSignaturesList, new PdfComparator());
			
			return pdfSignaturesList;

		} catch (SignatureException e) {
			throw new ValidationFatalException(e);
		} catch (IOException e) {
			throw new ValidationFatalException(e);
		} catch (CertificateException e) {
			throw new ValidationFatalException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new ValidationFatalException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new ValidationFatalException(e);
		} catch (KeyStoreException e) {
			throw new ValidationFatalException(e);
		} catch (CertStoreException e) {
			throw new ValidationFatalException(e);
		} catch (InvalidKeyException e) {
			throw new ValidationFatalException(e);
		} catch (NoSuchProviderException e) {
			throw new ValidationFatalException(e);
		} catch (CMSException e) {
			throw new ValidationFatalException(e);
		}
		
	}
	

	private static PDFSignatureInfo validateSignature(String name, AcroFields af, KeyStore ksCache, KeyStore ksTrust)
			throws CertificateException, SignatureException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			KeyStoreException, CertStoreException, InvalidKeyException, NoSuchProviderException, CMSException, IOException {
		
		PDFSignatureInfo pdfSignature = new PDFSignatureInfo(); 
		pdfSignature.setStatus(Status.UNKNOWN);
		
		try {
			pdfSignature.setName(name);

			log.info("Signature covers whole document: " + af.signatureCoversWholeDocument(name));
			log.info("Document revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());

			// // Start revision extraction
			// FileOutputStream out = new FileOutputStream("/home/alfredo/Escritorio/revision_" + af.getRevision(name) + ".pdf");
			// byte bb[] = new byte[8192];
			// InputStream ip = af.extractRevision(name);
			// int n = 0;
			// while ((n = ip.read(bb)) > 0)
			// out.write(bb, 0, n);
			// out.close();
			// ip.close();
			// // End revision extraction

			// PdfPKCS7 pk = af.verifySignature(name);
			PdfPKCS7 pk = af.verifySignature(name, "BC"); // BC ??????????????????

			if (!pk.verify()) {
				// documento modificado
				pdfSignature.setError(ValidationError.CORRUPT);
				pdfSignature.setStatus(Status.INVALID);
				throw new ValidationInterruptedException();
			}

			// STANDARD DATE
			pdfSignature.setDate(pk.getSignDate().getTime());

			// TIMESTAMP (un fallo en la validacion del ts no interrumpe el proceso de validacion de la firma)
			TimeStampToken token = pk.getTimeStampToken();
			
			if (token != null) {
				TimestampInfo timestampInfo = validateTimestamp(token, pk, ksCache, ksTrust);
				pdfSignature.setTimestampInfo(timestampInfo);
				if (timestampInfo.getStatus().equals(Status.VALID)) {
					Calendar timestampDate = pk.getTimeStampDate();
					pdfSignature.setDate(timestampDate.getTime());
				} else {
					// si el time stamp es invalido pongo la firma a warning
					pdfSignature.setStatus(Status.VALID_WARNING);
				}
			} else {
				// sin timestamp (hora local)
				pdfSignature.setStatus(Status.VALID_WARNING);
			}

			// SIGNATURE VERIFICATION
			Certificate pkc[] = pk.getSignCertificateChain();

			log.info("\n--------------Muestra la chain obtenida de la firma------------------");
			for (int k2 = 0; k2 < pkc.length; k2++) {
				X509Certificate certTemp = (X509Certificate) pkc[k2];
				log.info(certTemp.getSubjectX500Principal().getName());
			}
			log.info("\n------------------------------------------------");

			
			// BUILD AND VALIDATE THE CHAIN
			Set<CertStore> certStoreList = new HashSet<CertStore>();
			
			certStoreList.add(CertPathUtil.convert2CertStore(CertPathUtil.convert2CertPath(pkc)));
			
			certStoreList.add(CertPathUtil.convert2CertStore(ksCache));
			
			ChainInfo chainInfo = CertPathUtil.validateChain((X509Certificate) pkc[0], ksTrust, certStoreList, pdfSignature.getDate(), true);
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
			log.error("proceso de validacion interrumpido, resultado no valido");
		}
		
		return pdfSignature;
	}

	
	private boolean verifyTimestampImprint(TimeStampToken token, byte[] digest) throws NoSuchAlgorithmException {
		
        if (token == null) {
            return false;
        }
        MessageImprint imprint = token.getTimeStampInfo().toTSTInfo().getMessageImprint();
        byte[] md = MessageDigest.getInstance("SHA-1").digest(digest);
        byte[] imphashed = imprint.getHashedMessage();
        boolean res = Arrays.equals(md, imphashed);
        
        return res;
    }
	
	private static TimestampInfo validateTimestamp(TimeStampToken token, PdfPKCS7 pk, KeyStore ksCache, KeyStore ksTrust)
			throws KeyStoreException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CMSException,
			CertStoreException, CertificateException, IOException {

		TimestampInfo timestampInfo = new TimestampInfo();
		timestampInfo.setStatus(Status.UNKNOWN);
		
		try {
			
			TimeStampTokenInfo tstInfo = token.getTimeStampInfo();
			timestampInfo.setDate(tstInfo.getGenTime());
		
			// VERIFY IMPRINT
			if (!pk.verifyTimestampImprint()) {
				timestampInfo.setStatus(Status.INVALID);
				timestampInfo.setError(TimestampInfo.Error.CORRUPT);
				throw new TsValidationInterruptedException();
			}

			CertStore certStoreTimestamp = token.getCertificatesAndCRLs("Collection", null);

			Set<CertStore> certStoreList = new HashSet<CertStore>();
			certStoreList.add(certStoreTimestamp);
			certStoreList.add(CertPathUtil.convert2CertStore(ksCache));
			
			// VERIFY THE SIGNER
			X509Certificate signer = TimestampUtil.verifyTimestampCertificate(token, certStoreList, null);
			if (signer == null) {
				timestampInfo.setStatus(Status.UNKNOWN);
				timestampInfo.setError(TimestampInfo.Error.SIGNER_NOT_FOUND); // esto seria como un incomplete chain
				throw new TsValidationInterruptedException();
			}
			
			// BUILD AND VALIDATE THE CHAIN
			// paso la validacion sin ocsp
			ChainInfo chainInfo = CertPathUtil.validateChain(signer, ksTrust, certStoreList, tstInfo.getGenTime(), false);
			timestampInfo.setChainInfo(chainInfo);
			
			if (!chainInfo.getStatus().equals(Status.VALID)) {
				timestampInfo.setStatus(chainInfo.getStatus()); // valid_warning o unknown
				timestampInfo.setError(TimestampInfo.Error.CHAIN_ERROR);
				throw new TsValidationInterruptedException();
			}
			
			// solo si se llega hasta aqui es valido el ts
			timestampInfo.setStatus(Status.VALID);
			
		} catch (TsValidationInterruptedException e) {
			log.info("proceso de validacion interrumpido, resultado no valido");
		}
		
		log.info("proceso de validacion del ts terminado");
		return timestampInfo;
	}

	
}

// esto lo dejo aqui para la validacion de la ocsp interna

//// REVOCATION EMBEBED
//			
// System.out.println("Is revocation start?");
//			
// // embebed
// // pdfSignature.setSignerStatus(PDFSignatureInfo.SIGN__SIGNER_NOT_FOUND);
// BasicOCSPResp ocsp = pk.getOcsp();
//			
//			
//			
// if (ocsp != null) {
//				
// System.out.println("Is revocation valid?: "+ pk.isRevocationValid());
//				
//				
// // generate a Keystore with the ocsp certificates
// Collection<X509Certificate> ocspCertsList = null;
// try {
// CertStore store = ocsp.getCertificates("Collection", "BC");
// ocspCertsList = (Collection<X509Certificate>) store.getCertificates(new X509CertSelector());
//					
// } catch (NoSuchAlgorithmException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// } catch (NoSuchProviderException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// } catch (CertStoreException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// } catch (OCSPException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// }
//				
//				
// KeyStore ksOcsp = null;
// try {
// ksOcsp = KeyStore.getInstance(KeyStore.getDefaultType());
// ksOcsp.load(null, null);
// } catch (KeyStoreException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// } catch (NoSuchAlgorithmException e1) {
// // TODO Auto-generated catch block
// e1.printStackTrace();
// } catch (CertificateException e1) {
// // TODO Auto-generated catch block
// e1.printStackTrace();
// } catch (IOException e1) {
// // TODO Auto-generated catch block
// e1.printStackTrace();
// }
//				
//				
// for (X509Certificate certificate : ocspCertsList) {
//					
// try {
// ksOcsp.setCertificateEntry(CertificatePathBuilder.getUniqueID(certificate), certificate);
// System.out.println("ocsp CA certificates: " + certificate.getSubjectDN().getName());
//						
// // graba los cers a fichero
// try {
// FileOutputStream fos = new FileOutputStream("/home/alfredo/Escritorio/ocsp/" + certificate.getSubjectDN());
// fos.write(certificate.getEncoded());
// fos.close();
//							
// } catch (FileNotFoundException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// } catch (CertificateEncodingException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// } catch (IOException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// }
//						
// } catch (KeyStoreException e) {
//
// e.printStackTrace();
// }
// }
//				
//				
// X509Certificate ocspSignerCertificate = CertificatePathBuilder.verifyOcspCertificates(ocsp, ksOcsp, "BC");
//				
// if (ocspSignerCertificate != null) {
// // pdfSignature.setSignerStatus(PDFSignatureInfo.SIGN_VALID);
// System.out.println(ocspSignerCertificate.getSubjectDN());
// System.out.println("Are ocsp Certificates Trusted");
// }
//				
//				
//				
// }





