package net.esle.sinadura.core.xades;

import net.esle.sinadura.core.exceptions.XadesSignatureException;
import net.esle.sinadura.core.model.XadesSignaturePreferences;

import org.w3c.dom.Document;

import es.mityc.firmaJava.libreria.xades.DataToSign;
import es.mityc.firmaJava.libreria.xades.EnumFormatoFirma;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.javasign.xml.refs.InternObjectToSign;
import es.mityc.javasign.xml.refs.ObjectToSign;

/**
 * firma XAdES-BES para pruebas
 * 
 */
public class XAdESBESTestSignature extends GenericXMLSignature {

    XadesSignaturePreferences signaturePreferences;
    // TODO quitar path
    String path;
    
    
    public XAdESBESTestSignature(String path, XadesSignaturePreferences signaturePreferences) {
    	
    	this.path = path;
		this.signaturePreferences = signaturePreferences;
    }
    
    @Override
    protected DataToSign createDataToSign() throws XadesSignatureException {
    	
        DataToSign dataToSign = new DataToSign();
        dataToSign.setXadesFormat(EnumFormatoFirma.XAdES_BES);
        dataToSign.setEsquema(XAdESSchemas.XAdES_132);
        dataToSign.setXMLEncoding("UTF-8");
        dataToSign.setEnveloped(true);
        
//        dataToSign.addObject(new ObjectToSign(new AllXMLToSign(), "Documento de ejemplo", null, "text/xml", null));
        
        dataToSign.addObject(new ObjectToSign(new InternObjectToSign("titulo"), "Documento de ejemplo", null, "text/xml", null));
        
//        dataToSign.setParentSignNode("titulo");
        
        dataToSign.setParentSignNode("documento");

        Document docToSign = getDocument(path);
        dataToSign.setDocument(docToSign);
        return dataToSign;
    }

    @Override
    protected XadesSignaturePreferences getSignaturePreferences() {
        return signaturePreferences;
    }
}
