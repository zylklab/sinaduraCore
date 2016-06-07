package net.esle.sinadura.core.xades;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

import net.esle.sinadura.core.certificate.CertificateUtil;
import net.esle.sinadura.core.exceptions.OCSPUnknownUrlException;
import net.esle.sinadura.core.exceptions.XadesSignatureException;
import net.esle.sinadura.core.model.XadesSignaturePreferences;
import net.esle.sinadura.core.util.FileUtil;
import es.mityc.firmaJava.libreria.xades.DataToSign;
import es.mityc.firmaJava.libreria.xades.DataToSign.XADES_X_TYPES;
import es.mityc.firmaJava.libreria.xades.EnumFormatoFirma;
import es.mityc.firmaJava.libreria.xades.FirmaXML;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.javasign.certificate.ocsp.OCSPLiveConsultant;
import es.mityc.javasign.trust.TrustAbstract;
import es.mityc.javasign.xml.refs.ExternFileToSign;
import es.mityc.javasign.xml.refs.ObjectToSign;

/**
 * firma XAdES-X-L (construida sobre una XAdES-X tipo 1) detached
 * 
 */
public class XAdESXLDetachedSignature extends GenericXMLSignature {

	
	XadesSignaturePreferences signaturePreferences;
    // TODO quitar path
    String path;

    
    public XAdESXLDetachedSignature(String path, XadesSignaturePreferences signaturePreferences) {
    	
    	this.path = path;
		this.signaturePreferences = signaturePreferences;
    }

    @Override
    protected DataToSign createDataToSign() throws XadesSignatureException, OCSPUnknownUrlException {
    	
        DataToSign dataToSign = new DataToSign();
        dataToSign.setXadesFormat(EnumFormatoFirma.XAdES_XL);
        dataToSign.setXAdESXType(XADES_X_TYPES.TYPE_1);
        dataToSign.setEsquema(XAdESSchemas.XAdES_132);
        dataToSign.setXMLEncoding("UTF-8");
        dataToSign.setEnveloped(false);
        
        // TODO
//        TrustAbstract truster = TrustFactory.getInstance().getTruster(TRUSTER_NAME);
        TrustAbstract truster = new KeystoreTruster(signaturePreferences.getKsCache());
        
        // fijar ocsp
		try {
			// TODO comprobar con p12, classCastException??
			X509Certificate certificate = (X509Certificate) signaturePreferences.getKsSignaturePreferences().getKs().getCertificate(
					signaturePreferences.getKsSignaturePreferences().getAlias());
	        String ocspUrl = CertificateUtil.getOCSPURL(certificate);
	        dataToSign.setCertStatusManager(new OCSPLiveConsultant(ocspUrl, truster));
	        
		} catch (KeyStoreException e) {
			throw new XadesSignatureException(e);
		}

		System.out.println("usesSystemProxies: " + System.getProperty("java.net.useSystemProxies")); 

		try {
			URI file = new URI(FileUtil.normaliceLocalURI(this.path));
			URI base = FileUtil.getParentFolder(file);
			
			String baseUtf8 = null;
			baseUtf8 = base.toASCIIString();
			dataToSign.setBaseURI(baseUtf8);
			
			dataToSign.addObject(new ObjectToSign(new RelativeExternFileToSign(new File (file), baseUtf8), "signed by sinadura", null, "text/xml", null));
			
			// prueba de url absoluta
//		    dataToSign.addObject(new ObjectToSign(new ExternFileToSign(new File("/home/alfredo/Escritorio/original.txt"), "#"),  "Documento de ejemplo", null, "text/xml", null));
	        
	        return dataToSign;
	        
		} catch (URISyntaxException e) {
			e.printStackTrace();
			throw new XadesSignatureException(e);
		}catch(Exception e){
			e.printStackTrace();
			throw new XadesSignatureException(e);
		}
		
    }


    @Override
    protected FirmaXML createFirmaXML() {
        FirmaXML firmaXML = super.createFirmaXML();
        firmaXML.setTSA(signaturePreferences.getTimestampUrl());
        return firmaXML;
    }
    
    @Override
    protected XadesSignaturePreferences getSignaturePreferences() {
        return signaturePreferences;
    }

}
