
package net.esle.sinadura.core.xades;

import java.io.File;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.implementations.ReseteableFileInputStream;
import org.apache.xml.utils.URI;
import org.w3c.dom.Attr;

import es.mityc.javasign.xml.resolvers.MITyCResourceResolver;

/**
 * This ResourceResolver allows to access to filesystem without bytereaded in signature management (improves memory management with some
 * signatures sign/validation when not accesing such files through XmlSignature structure).
 * 
 * @author dsantose
 */
public class Utf8ResolverBigLocalFileSystem extends MITyCResourceResolver {
	

	static org.apache.commons.logging.Log log = org.apache.commons.logging.LogFactory.getLog(Utf8ResolverBigLocalFileSystem.class.getName());

	public boolean engineIsThreadSafe() {
		return true;
	}

	public XMLSignatureInput engineResolve(Attr uri, String BaseURI) throws ResourceResolverException {

		try {
			URI uriNew = getNewURI(uri.getNodeValue(), BaseURI);

			// if the URI contains a fragment, ignore it
			URI uriNewNoFrag = new URI(uriNew);

			uriNewNoFrag.setFragment(null);

//			String fileName =
//				ResolverLocalFilesystem
//				.translateUriToFilename(uriNewNoFrag.toString());
			
			// alfredo -> para paths utf8 
			java.net.URI javaUri = new java.net.URI(uriNewNoFrag.toString());
			File file = new File(javaUri);
			String fileName = file.getAbsolutePath();
			//
			
			ReseteableFileInputStream inputStream = new ReseteableFileInputStream(fileName);
			XMLSignatureInput result = new XMLSignatureInput(inputStream);

			result.setSourceURI(uriNew.toString());

			return result;
			
		} catch (Exception e) {
			throw new ResourceResolverException("generic.EmptyMessage", e, uri, BaseURI);
		}
	}
	

	public boolean engineCanResolve(Attr uri, String BaseURI) {

		if (uri == null) {
			return false;
		}

		String uriNodeValue = uri.getNodeValue();

		if (uriNodeValue.equals("") || (uriNodeValue.charAt(0) == '#') || uriNodeValue.startsWith("http:")) {
			return false;
		}

		try {
			// URI uriNew = new URI(new URI(BaseURI), uri.getNodeValue());
			if (log.isDebugEnabled())
				log.debug("I was asked whether I can resolve " + uriNodeValue/* uriNew.toString() */);

			if (uriNodeValue.startsWith("file:") || BaseURI.startsWith("file:")/* uriNew.getScheme().equals("file") */) {
				if (log.isDebugEnabled())
					log.debug("I state that I can resolve " + uriNodeValue/* uriNew.toString() */);

				return true;
			}
		} catch (Exception e) {
		}

		log.debug("But I can't");

		return false;
	}

	protected static URI getNewURI(String uri, String BaseURI) throws URI.MalformedURIException {

		if ((BaseURI == null) || "".equals(BaseURI)) {
			return new URI(uri);
		}
		return new URI(new URI(BaseURI), uri);
	}

	private static int FILE_URI_LENGTH = "file:/".length();
	// borrar si no se usa
	protected static String translateUriToFilename(String uri) {

	      String subStr = uri.substring(FILE_URI_LENGTH);

	      if (subStr.indexOf("%20") > -1)
	      {
	        int offset = 0;
	        int index = 0;
	        StringBuffer temp = new StringBuffer(subStr.length());
	        do
	        {
	          index = subStr.indexOf("%20",offset);
	          if (index == -1) temp.append(subStr.substring(offset));
	          else
	          {
	            temp.append(subStr.substring(offset,index));
	            temp.append(' ');
	            offset = index+3;
	          }
	        }
	        while(index != -1);
	        subStr = temp.toString();
	      }

	      if (subStr.charAt(1) == ':') {
	      	 // we're running M$ Windows, so this works fine
	         return subStr;
	      }
	      // we're running some UNIX, so we have to prepend a slash
	      return "/" + subStr;
	   }
	
}
