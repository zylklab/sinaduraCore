
package net.esle.sinadura.core.xades;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URI;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.firmaJava.libreria.utilidades.URIEncoder;
import es.mityc.javasign.xml.refs.AbstractObjectToSign;
import es.mityc.javasign.xml.resolvers.MITyCResourceResolver;
import es.mityc.javasign.xml.resolvers.ResolverPrivateData;

/**
 * Corregida la clase para que el relativize funcione correctamente en windows.
 * 
 * Y añadido el resolver para paths utf8.
 * 
 */
public class RelativeExternFileToSign extends AbstractObjectToSign {
	
	private static Log log = LogFactory.getLog(RelativeExternFileToSign.class);
	
	private File file;
	/** BaseUri de la firma donde irá este objeto. */
	private String base;
	
	public RelativeExternFileToSign(File file, String baseUri) {
		this.file = file;
		this.base = baseUri;
	}

	/**
	 * @return the file
	 */
	public File getFile() {
		return file;
	}

	/**
	 * @param file the file to set
	 */
	public void setFile(File file) {
		this.file = file;
	}
	
	/**
	 * @see es.mityc.javasign.xml.refs.AbstractObjectToSign#getReferenceURI()
	 */
	@Override
	public String getReferenceURI() {
		
		return relativizeRute(base, file);
	}
	
	/**
     * <p>Devuelve la ruta a un fichero relativa a la base indicada.</p> 
     * @param baseUri Base sobre la que se relativiza la ruta
     * @param file Fichero del que se calcula la ruta
     * @return ruta relativizada
     */
	private String relativizeRute(String baseUri, File file) {
		
		String strFile = null;
//		try {
			URI fileUri = file.toURI();
//			String fileUtf8 = URIEncoder.encode(fileUri.toString(), "UTF-8");
			String fileUtf8 = fileUri.toASCIIString();
			strFile = URIEncoder.relativize(baseUri, fileUtf8);
			
//		} catch (UnsupportedEncodingException e) {
//			log.error("", e);
//		}
		
		return strFile;
    }
	
	// para corregir el tema de utf8
	@Override
	public MITyCResourceResolver getResolver() {
		return new Utf8ResolverBigLocalFileSystem();
	}
}
