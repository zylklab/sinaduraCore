package net.esle.sinadura.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SignatureSpi;

import net.esle.sinadura.console.Sinadura;

import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.FileSystemManager;
import org.apache.commons.vfs2.VFS;




public class TestSinadura {

		
	
	public static void testSardine(String[] args) throws Exception {

		
//		try {
//			InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("net/else/sinadura/core/log4j.properties");
//			Properties configuration = new Properties();
//			configuration.load(is);
//			PropertyConfigurator.configure(PropertiesCoreUtil.getProperties2());
//			
//		} catch (IOException e) {
//			log.error("", e);
//		}
		
		
		// Parseo de los argumentos
		
		String inputDav = "/home/gus/Escritorio/test.pdf";
		//String inputFile = "/home/gus/Escritorio/test.pdf";
		
		String outDav = "/home/gus/Escritorio/test-ss.pdf";
		
		
		String[] args2 ={"--input",inputDav,"--output",outDav,"--preferences","/home/gus/Escritorio/preferences-sinadura-console.properties","--sign","--pdf"};
		
		Sinadura.main(args2);
		
		}
	
	public static void main(String[] args) throws Exception {
		testSardine(args);
	}
	
	
	public static void testVFS() throws IOException
	{
		FileSystemManager fsManager = VFS.getManager();
		

		
		FileObject sourceFolder = fsManager.resolveFile("/home/gus/Escritorio");
		FileObject sourceFile = sourceFolder.resolveFile("test.pdf");

		
		
		FileObject destFolder = fsManager.resolveFile("/home/gus/Escritorio");
//		destFolder = destFolder.resolveFile("Zylk");
//		destFolder = destFolder.resolveFile("zadmin");
//		destFolder = destFolder.resolveFile("test-sinadura23");
		FileObject destFile = destFolder.resolveFile("casa228.pdf");
		
//		FileObject destFile2 = fsManager.resolveFile("webdav://gfg001:6eriloloSeguro@services.zylk.net/alfresco/webdav/Zylk/zadmin/test-sinadura/test314.pdf");
		
		//org.apache.jackrabbit.webdav.client.methods.DavMethod a WebdavFileObject;
		
		
		
		InputStream is = sourceFile.getContent().getInputStream();
		OutputStream os = destFile.getContent().getOutputStream();
		
		IOUtils.copy(is, os);
		destFile.close();
		sourceFile.close();
		
		
		//destinationFile.copyFrom(sourceFile, null);
		
		//destinationFile.getContent().getOutputStream();
		
	}
}
