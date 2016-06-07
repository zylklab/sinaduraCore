package net.esle.sinadura.core.xades;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;

import net.esle.sinadura.core.exceptions.XadesSignatureException;
import net.esle.sinadura.core.model.XadesSignaturePreferences;
import net.esle.sinadura.core.util.FileUtil;
import es.mityc.firmaJava.libreria.xades.DataToSign;
import es.mityc.firmaJava.libreria.xades.EnumFormatoFirma;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.javasign.xml.refs.ObjectToSign;

/**
 * Clase de ejemplo para la firma XAdES-BES detached de un documento. 
 */
public class XAdESBESDetachedSignature extends GenericXMLSignature {

	XadesSignaturePreferences signaturePreferences;
    String path;
	
    public XAdESBESDetachedSignature(String path, XadesSignaturePreferences signaturePreferences) {
    	
    	this.path = path;
		this.signaturePreferences = signaturePreferences;
    }
    
    @Override
    protected DataToSign createDataToSign() throws XadesSignatureException {
    	
        DataToSign dataToSign = new DataToSign();
        dataToSign.setXadesFormat(EnumFormatoFirma.XAdES_BES);
        dataToSign.setEsquema(XAdESSchemas.XAdES_132);
        dataToSign.setXMLEncoding("UTF-8");
        dataToSign.setEnveloped(false);
        
		try {
			URI file = new URI(FileUtil.normaliceLocalURI(this.path));
			URI base = FileUtil.getParentFolder(file);
			
			String baseUtf8 = null;
			baseUtf8 = base.toASCIIString();
			dataToSign.setBaseURI(baseUtf8);
			
			dataToSign.addObject(new ObjectToSign(new RelativeExternFileToSign(new File (file), baseUtf8), "signed by sinadura", null, "text/xml", null));
	        
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
    protected XadesSignaturePreferences getSignaturePreferences() {
        return signaturePreferences;
    }
}
