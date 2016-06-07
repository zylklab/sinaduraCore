package net.esle.sinadura.core.xades;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import net.esle.sinadura.core.certificate.CertificateUtil;
import net.esle.sinadura.core.exceptions.OCSPUnknownUrlException;
import net.esle.sinadura.core.exceptions.XadesSignatureException;
import net.esle.sinadura.core.model.XadesSignaturePreferences;
import net.esle.sinadura.core.service.PdfService;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import es.mityc.firmaJava.libreria.xades.DataToSign;
import es.mityc.firmaJava.libreria.xades.DataToSign.XADES_X_TYPES;
import es.mityc.firmaJava.libreria.xades.EnumFormatoFirma;
import es.mityc.firmaJava.libreria.xades.FirmaXML;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.javasign.certificate.ocsp.OCSPLiveConsultant;
import es.mityc.javasign.trust.TrustAbstract;
import es.mityc.javasign.xml.refs.AllXMLToSign;
import es.mityc.javasign.xml.refs.ObjectToSign;


public class XAdESFacturaeSignature extends GenericXMLSignature {

	private static Log log = LogFactory.getLog(XAdESFacturaeSignature.class);
	
	XadesSignaturePreferences signaturePreferences;
	InputStream document;

    
    public XAdESFacturaeSignature(InputStream document, XadesSignaturePreferences signaturePreferences) {
    	
    	this.document = document;
		this.signaturePreferences = signaturePreferences;
    }

    @Override
    protected DataToSign createDataToSign() throws XadesSignatureException, OCSPUnknownUrlException {
    	

    	// deteccion de la version de facturae
    	String facturaeVersion;
    	try {
			// Lo paso a byte[] porque necesito leer dos veces el InputStream (para obtener la version de facturae). Con las
			// facturas no pesan mucho de momento lo dejo asi. Se podria evitar/corregir esto reaprobechando el objeto "Document"
			// (dom) y leyendo la version de facturae (xpath) con el setNamespaceAware a true.
    		ByteArrayOutputStream baos = new ByteArrayOutputStream();    	
			IOUtils.copy(document, baos);			
	    	byte[] documentBytes = baos.toByteArray();
	    	facturaeVersion = this.detectFacturaeVersion(documentBytes);

	    	this.document = new ByteArrayInputStream(documentBytes);
			
		} catch (IOException e) {
			throw new XadesSignatureException(e);
		} catch (XPathExpressionException e) {
			throw new XadesSignatureException(e);
		} catch (ParserConfigurationException e) {
			throw new XadesSignatureException(e);
		} catch (SAXException e) {
			throw new XadesSignatureException(e);
		}
    	//
    	
        DataToSign dataToSign = new DataToSign();
        
        if (signaturePreferences.getAddOCSP() && signaturePreferences.getTimestampUrl() != null
				&& !signaturePreferences.getTimestampUrl().equals("")) {
        	dataToSign.setXadesFormat(EnumFormatoFirma.XAdES_XL);
        	dataToSign.setXAdESXType(XADES_X_TYPES.TYPE_1);
		} else if (signaturePreferences.getTimestampUrl() != null && !signaturePreferences.getTimestampUrl().equals("")) {
        	dataToSign.setXadesFormat(EnumFormatoFirma.XAdES_T);
        } else {
        	dataToSign.setXadesFormat(EnumFormatoFirma.XAdES_BES);
        }
        
        dataToSign.setXMLEncoding("UTF-8");
        dataToSign.setEnveloped(true);

		if (signaturePreferences.getAddOCSP() && signaturePreferences.getTimestampUrl() != null
				&& !signaturePreferences.getTimestampUrl().equals("")) { // si es XL
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
        }

		Document docToSign = getDocument(document);
		dataToSign.setDocument(docToSign);
		    
		dataToSign.addObject(new ObjectToSign(new AllXMLToSign(), "Documento de ejemplo", null, "text/xml", null));

		dataToSign.setAddPolicy(true);
		
		if (facturaeVersion.equals("3.0")) {
			dataToSign.setPolicyKey("facturae30");
			dataToSign.setEsquema(XAdESSchemas.XAdES_122);
			
		} else if (
				facturaeVersion.equals("3.1") || 
				facturaeVersion.equals("3.2") || 
				facturaeVersion.equals("3.2.1")
			){
			dataToSign.setPolicyKey("facturae31");
			dataToSign.setEsquema(XAdESSchemas.XAdES_132);
			
		} else {
			throw new XadesSignatureException("unknown facturae policy");
		}
		
        return dataToSign;
    }


    @Override
    protected FirmaXML createFirmaXML() {
    	
        FirmaXML firmaXML = super.createFirmaXML();
		if (signaturePreferences.getTimestampUrl() != null && !signaturePreferences.getTimestampUrl().equals("")) { // si es T o XL
			firmaXML.setTSA(signaturePreferences.getTimestampUrl());
        }
        return firmaXML;
    }
    
    @Override
    protected XadesSignaturePreferences getSignaturePreferences() {
        return signaturePreferences;
    }
    
    // Logica para identificar la version de facturae
	private String detectFacturaeVersion(byte[] bytes) throws ParserConfigurationException, SAXException, IOException,
			XPathExpressionException {
    	
        DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
        domFactory.setNamespaceAware(false);
        DocumentBuilder builder = domFactory.newDocumentBuilder();
        InputStream is = new ByteArrayInputStream(bytes);
        Document doc = builder.parse(is);
        XPath xpath = XPathFactory.newInstance().newXPath();        
        XPathExpression expr = xpath.compile("/Facturae/FileHeader/SchemaVersion");
        Node node = (Node) expr.evaluate(doc, XPathConstants.NODE);
        String facturaeVersion = node.getTextContent();
        
        log.info("facturae detectado: " + facturaeVersion);
        
        return facturaeVersion;
    }

}
