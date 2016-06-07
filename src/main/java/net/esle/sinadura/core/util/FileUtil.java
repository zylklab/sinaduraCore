package net.esle.sinadura.core.util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.FileNameMap;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.util.URIUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.FileSystemException;
import org.apache.commons.vfs2.FileSystemManager;
import org.apache.commons.vfs2.VFS;
import org.apache.commons.vfs2.impl.StandardFileSystemManager;
import org.apache.commons.vfs2.util.Os;

import es.mityc.firmaJava.libreria.utilidades.URIEncoder;

public class FileUtil {

	// TODO quitar los metodos que este repetido resptecto a el commons-io de apache (copyFile...)
	
	private static Log log = LogFactory.getLog(FileUtil.class);

	public static final String MIMETYPE_PDF = "application/pdf";
	public static final String MIMETYPE_XML = "application/xml"; // hay tambien text/xml pero la funcion esta basada en la extension asi que
	// siempre va a devolver el otro
	public static final String MIMETYPE_SAR = "application/sar";
	
	public static final String MIMETYPE_CXSIG = "application/cxsig";

	public static final String MIMETYPE_P7S = "application/pkcs7-signature";

	public static final String EXTENSION_SAR = "sar";
	public static final String EXTENSION_CXSIG = "cxsig";
	public static final String EXTENSION_PDF = "pdf";
	public static final String EXTENSION_XML = "xml";
	public static final String EXTENSION_ZIP = "zip";
	public static final String EXTENSION_P7S = "p7s";
	public static final String EXTENSION_CER = "cer";
	public static final String EXTENSION_CRT = "crt";
	public static final String EXTENSION_P12 = "p12";
	public static final String EXTENSION_PFX = "pfx";
	public static final String EXTENSION_PNG = "png";
	public static final String EXTENSION_JPG = "jpg";
	public static final String EXTENSION_GIF = "gif";

	
	public static String cleanName(String name) {

		
		return "alfredo.odt";
	}
	
	
	public static String getExtension(File file) {

		String name = file.getName();
		return getExtension(name);
	}

	public static String getExtension(String s) {

		return (s.substring(s.lastIndexOf('.') + 1, s.length()));
	}

	public static String getMimeType(String fileUrl) {

		FileNameMap fileNameMap = URLConnection.getFileNameMap();
		String type = fileNameMap.getContentTypeFor(fileUrl);

		// si no lo reconoce
		if (type == null) {
			String extension = FileUtil.getExtension(fileUrl);
			if (extension.equals(EXTENSION_P7S)) {
				type = MIMETYPE_P7S;
			} else if (extension.equals(EXTENSION_SAR)) {
				type = MIMETYPE_SAR;
			} else if (extension.equals(EXTENSION_CXSIG)) {
				type = MIMETYPE_CXSIG;
			}
		}

		log.info("mimetype: " + type);

		return type;
	}

	// TODO pasar paths a Files
	public static void deleteFile(String fileName) {

		// A File object to represent the filename
		File f = new File(fileName);

		// Make sure the file or directory exists and isn't write protected
		if (!f.exists())
			log.error("Delete: no such file or directory: " + fileName);

		if (!f.canWrite())
			log.error("Delete: write protected: " + fileName);

		// If it is a directory, make sure it is empty
		if (f.isDirectory()) {
			String[] files = f.list();
			if (files.length > 0)
				log.error("Delete: directory not empty: " + fileName);
		}

		// Attempt to delete it
		boolean success = f.delete();

		if (!success)
			log.error("Delete: deletion failed");
	}

	
	public static void copyFile(String srFile, String dtFile) {

		try {
			InputStream in = getInputStreamFromURI(srFile);
			OutputStream out = getOutputStreamFromURI(dtFile);

			IOUtils.copy(in, out);
			
			in.close();
			out.close();

		} catch (FileNotFoundException e) {
			log.error(e.getMessage() + " in the specified directory.", e);

		} catch (IOException e) {
			log.error("", e);
		} catch (URISyntaxException e) {
			log.error("", e);
		}
	}

	
	/**
	 * Por defecto recursive a true
	 * 
	 * @param dirFile
	 * @return
	 */
	public static List<File> getFilesFromDir(File dirFile) {
		
		return getFilesFromDir(dirFile, null, true);
	}
	
	public static List<File> getFilesFromDir(File dirFile, boolean recursive) {
		
		return getFilesFromDir(dirFile, null, recursive);
	}

	/**
	 * Por defecto recursive a true
	 * 
	 * @param dirFile
	 * @param extensions
	 * @return
	 */
	public static List<File> getFilesFromDir(File dirFile, String[] extensions) {
		
		return getFilesFromDir(dirFile, extensions, true);
	}
	
	public static List<File> getFilesFromDir(File dirFile, String[] extensions, boolean recursive) {

		List<File> fileList = new ArrayList<File>();
		File[] files = dirFile.listFiles();

		for (File file : files) {
			if (file.isDirectory()) {
				if (recursive) {
					List<File> fileList2 = getFilesFromDir(file, extensions);
					for (File file2 : fileList2) {
						fileList.add(file2);
					}
				}
			} else {
				if (extensions != null) {
					for (String extension : extensions) {
						if (file.getName().toLowerCase().endsWith(extension)) {
							fileList.add(file);
							break;
						}
					}
				} else {
					fileList.add(file);
				}
			}
		}
		
		return fileList;
	}

	// ////////////////////// TODO revisar

//	public static void zipDir(String dir, String file, boolean compress) throws IOException {
//
//		FileOutputStream fout = new FileOutputStream(file);
//		ZipOutputStream zout = new ZipOutputStream(fout);
//		FileUtil.zipDir(dir, zout, compress, dir + File.separatorChar);
//		zout.close();
//		fout.close();
//	}
	
	public static byte[] zipDir(String dir, boolean compress) throws IOException {
		return zipDir(dir, compress, "utf-8", true, false);
		
	}
	
	private static byte[] zipDir(String dir, boolean compress, String encoding, boolean withEFS, boolean withExplicitUnicodeExtra) throws IOException {

		ByteArrayOutputStream fout = new ByteArrayOutputStream();
		ZipArchiveOutputStream zout = new ZipArchiveOutputStream(fout);
		zout.setEncoding(encoding);
		zout.setUseLanguageEncodingFlag(withEFS);
//		zout.setCreateUnicodeExtraFields(withExplicitUnicodeExtra ? ZipArchiveOutputStream.UnicodeExtraFieldPolicy.NEVER
//				: ZipArchiveOutputStream.UnicodeExtraFieldPolicy.ALWAYS);

			FileUtil.zipDir(dir, zout, compress, dir + File.separator);
		zout.close();
		fout.close();
		return fout.toByteArray();
		
	}

	private static void zipDir(String dir2zip, ZipArchiveOutputStream zos, boolean compress, String prefix) throws IOException {

		// create a new File object based on the directory we have to zip
		// File
		File zipDir = new File(dir2zip);		
		// get a listing of the directory content
		String[] dirList = zipDir.list();
		byte[] buffer = new byte[1024];
		int bytesRead;
		// loop through dirList, and zip the files
		
		for (int i = 0; i < dirList.length; i++) {

			File f = new File(zipDir, dirList[i]);
			if (f.isDirectory()) {

				// if the File object is a directory, call this
				// function again to add its content recursively
				String filePath = f.getPath();
				zipDir(filePath, zos, compress, prefix);
				// loop again
				continue;
				
			}
			// if we reached here, the File object f was not a directory
			// create a FileInputStream on top of f
			FileInputStream fis = new FileInputStream(f);

			BufferedInputStream bis = new BufferedInputStream(fis);

			/*
			 * El substring o lo que sea es para no meter la ruta entera del fichero comprimido sino solo el fichero
			 * #13260 - se normalizan las barras para que los SAR sean compatibles en linux
			 */
			ZipArchiveEntry anEntry = new ZipArchiveEntry(FileUtil.normalizarBarras(f.getPath()).replace(FileUtil.normalizarBarras(prefix), ""));
	 
			zos.putArchiveEntry(anEntry);
			// now write the content of the file to the ZipOutputStream
			while ((bytesRead = bis.read(buffer)) != -1) {
				zos.write(buffer, 0, bytesRead);
			}
			bis.close();
			zos.closeArchiveEntry();
			// close the Stream
			fis.close();
		}
	}

	public static void copyDirectory(File sourceLocation, File targetLocation) throws IOException {

		if (sourceLocation.isDirectory()) {
			if (!targetLocation.exists()) {
				targetLocation.mkdir();
			}

			String[] children = sourceLocation.list();
			for (int i = 0; i < children.length; i++) {
				copyDirectory(new File(sourceLocation, children[i]), new File(targetLocation, children[i]));
			}
		} else {
			InputStream in = new FileInputStream(sourceLocation);
			OutputStream out = new FileOutputStream(targetLocation);

			// Copy the bits from instream to outstream
			byte[] buf = new byte[1024];
			int len;
			while ((len = in.read(buf)) > 0) {
				out.write(buf, 0, len);
			}
			in.close();
			out.close();
		}
	}

	public static void unzipIntoDirectory(String file, String dir) throws IOException, URISyntaxException {

		unzipIntoDirectory(getInputStreamFromURI(file), new File(dir));
	}
	
	public static void unzipIntoDirectory(InputStream is, String dir) throws IOException, URISyntaxException {

		unzipIntoDirectory(is, new File(dir));
	}

	private static void unzipIntoDirectory(InputStream is, File output) throws IOException {

		final int BUFFER = 2048;

		ZipArchiveInputStream zis = new ZipArchiveInputStream(new BufferedInputStream(is), "cp437", true);

		ZipEntry entry;
		while ((entry = zis.getNextZipEntry()) != null) {

			File file = new File(output, entry.getName());
			if (entry.isDirectory()) {
				file.mkdirs();
			} else {
				if (!file.getParentFile().exists()) {
					file.getParentFile().mkdirs();
				}
				int count;
				byte data[] = new byte[BUFFER];
				FileOutputStream fos = new FileOutputStream(file.getAbsolutePath());
				BufferedOutputStream dest = new BufferedOutputStream(fos, BUFFER);
				while ((count = zis.read(data, 0, BUFFER)) != -1) {
					dest.write(data, 0, count);
				}
				dest.flush();
				dest.close();
			}
		}

		zis.close();
	}

	
	public static boolean deleteDir(String dir) {

		return deleteDir(new File(dir));
	}
	
	public static boolean deleteDir(File dir) {

		if (dir.isDirectory()) {
			String[] children = dir.list();
			for (int i = 0; i < children.length; i++) {
				boolean success = deleteDir(new File(dir, children[i]));
				if (!success) {
					return false;
				}
			}
		}
		// The directory is now empty so now it can be smoked
		return dir.delete();
	}

	public static byte[] getBytesFromFile(File file) throws IOException {

		if (!file.exists()){
			throw new IOException("El fichero " + file.getPath() + " no existe");
		}
		InputStream is = new FileInputStream(file);

		// Get the size of the file
		long length = file.length();

		if (length > Integer.MAX_VALUE) {
			// File is too large
		}

		// Create the byte array to hold the data
		byte[] bytes = new byte[(int) length];

		// Read in the bytes
		int offset = 0;
		int numRead = 0;
		while (offset < bytes.length && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
			offset += numRead;
		}

		// Ensure all the bytes have been read in
		if (offset < bytes.length) {
			throw new IOException("Could not completely read file " + file.getName());
		}

		// Close the input stream and return bytes
		is.close();
		return bytes;
	}
	
	public static void export(Certificate cert, File file, boolean binary) throws CertificateEncodingException, IOException{
	    try {
	        byte[] buf = cert.getEncoded();
	        FileOutputStream os = new FileOutputStream(file);
	        
	        // binary form
	        if (binary) {
	            os.write(buf);

	        // text form
	        } else {
	            Writer wr = new OutputStreamWriter(os, Charset.forName("UTF-8"));
	            wr.write("-----BEGIN CERTIFICATE-----\n");
	            wr.write(new sun.misc.BASE64Encoder().encode(buf));
	            wr.write("\n-----END CERTIFICATE-----\n");
	            wr.flush();
	        }
	        os.close();
	    } catch (CertificateEncodingException e) {
	    	throw e;
	    	
	    } catch (IOException e) {
	    	throw e;
	    }
	}
	

	public static void bytesToFile(byte[] str, String f) throws IOException {

		try{
			// hacemos normalización local porque bytesToFile solo se deberia usar en local
			bytesToFile(str, new URI(normaliceLocalURI(f)));
			
		}catch(URISyntaxException e){
			e.printStackTrace();
			throw new IOException(e);
		}
	}
	
	public static void bytesToFile(byte[] str, URI f) throws IOException{
		try{
			OutputStream os = getOutputStreamFromURI(f.toString());
			os.write(str);
			os.flush();
			os.close();
			
		}catch(URISyntaxException e){
			e.printStackTrace();
			throw new IOException(e);
		}
	}
	
	
	public static InputStream getInputStreamFromURI(String inputFile) throws URISyntaxException, IOException
	{
		URI inputFileUri = normalizarURI(inputFile);
		FileSystemManager fsManager = VFS.getManager();
		FileObject sourceFile = fsManager.resolveFile(inputFileUri.toString());
		return sourceFile.getContent().getInputStream();
	}
	
	public static OutputStream getOutputStreamFromURI(String inputFile) throws URISyntaxException, IOException
	{
		URI inputFileUri = normalizarURI(inputFile);
		String normalizedPath = inputFileUri.toString();
		

		/*
		 * - alfresco necesita hacer las operación de escritura en 2 partes
		 * - norm. windows: en windows si procesamos file:/C:/ nos daría file:/c: como ruta base, y eso es malformed
		 * - tener en cuenta paths relativos sin jerarquía, pe: inputFile = 'algo.pdf'
		 */
		String folderPath = "";
		if (normalizedPath.contains("/")){
			folderPath = normalizedPath.substring(0,normalizedPath.lastIndexOf("/"));
			if (folderPath.endsWith(":")){
				folderPath += "/";
			}
		}

		// resolución de paths relativos
//		FileSystemManager fsManager = VFS.getManager();
		StandardFileSystemManager fsManager = new  StandardFileSystemManager();
		fsManager.init();
		fsManager.setBaseFile(new File(""));
		FileObject destFolder = fsManager.resolveFile(folderPath);	
		fsManager.close();
		
		FileObject destFile = destFolder.resolveFile(normalizedPath.substring(normalizedPath.lastIndexOf("/")+1, normalizedPath.length()));
		return destFile.getContent().getOutputStream();
	}
	
	public static String getFileName(String fileUri)
	{
		return fileUri.substring(fileUri.lastIndexOf("/")+1,fileUri.length());
	}
	
	public static URI getParentFolder(URI file) throws URISyntaxException
	{
		return file.getPath().endsWith("/") ? file.resolve("..") : file.resolve(".");
	}


	
	/******************************************
	 * Metodo que se asegura de que el string tiene formato URI con schema :// ...
	 * - Canal de entrada 2. por aquí pueden llegar temporales del sar
	 * @see DocumeInfoUtil#DocumentInfo
	 *******************************************/
	public static String normaliceLocalURI(String path) throws URISyntaxException{
		
		try {
			
			// normalización para windows
			path = normalizarBarras(path);
			
			// si está encodeado no lo reencodeamos
			//
			path = (isURIEncoded(path)?path:URIEncoder.encode(path, "utf-8"));
			
			// TODO revisar!! encode de los caracteres "[" y "]"
			path = path.replace("[", "%5B");
			path = path.replace("]", "%5D");
			
			// protocolo samba
//			path = (path.startsWith("//"))?"smb:" + path:path;
			/*
			 * @nota, no convertimos // en smb:// porque esto requeriría llevar user y password y no hay forma de insertarlo ahora.
			 * Sin embargo // puede ser ya un path de un enlace directo en windows, previamente autenticado y funciona
			 */
			
			/*
			 * si no tiene un schema soportado lo insertamos
			 * - protocolo samba
			 * - protocolo sinadura
			 * - protocolo webdav
			 * - protocolo gestor de ficheros
			 * 
			 * Se podría usar URI#getSchema, pero en windows, una URI de C:/ pilla el schema como 'C:/'
			 */
			if (!path.startsWith("//") && !path.startsWith("sinadura") && !path.startsWith("webdav") && !path.startsWith("file")){
				/**
				 * es file:/// y no file :// porque en windows si va con file://c: toma c como puerto =|
				 */
				path = "file:///" + path;
			}
			return path;
		} catch (UnsupportedEncodingException e) {
			throw new URISyntaxException(path, e.toString());
		}
	}
	
	public static String urlEncoder(String uri) throws UnsupportedEncodingException{
		if (!isURIEncoded(uri)){
			return URIEncoder.encode(uri, "utf-8");			
		}
		
		return uri;
	}

	/**
	 * Si el acceso no es file:// no se puede hacer xades
	 */
	public static boolean isXadesEnabled(String path){
//		return (!path.startsWith("webdav") && !path.startsWith("sinadura") && !path.startsWith("//"));
		
		try {
			path = FileUtil.normaliceLocalURI(path);
			URI uri = new URI(path);
			return (uri.getScheme() != null && uri.getScheme().equals("file"));
		} catch (URISyntaxException e) {
			e.printStackTrace();
			return false;
		}
	}
	
		
	/**
	 * Método que elimina el file:/ de un path para que se pueda tratar en local
	 * como file. Si no suele fallar
	 */
	public static File getLocalFileFromURI(String targetPath){
		File targetFile = new File(getLocalPathFromURI(targetPath));
		return targetFile;
	}
	
	public static String getLocalPathFromURI(URI path){
		return getLocalPathFromURI(path.toString());
	}
	public static String getLocalPathFromURI(String targetPath){
		try {
			
			// normalización para windows
			targetPath = normalizarBarras(targetPath);
						
			// quitamos schema
			if (targetPath.startsWith("file")){
				targetPath = targetPath.replace("file:///", "");
				targetPath = targetPath.replace("file://", "");
				targetPath = targetPath.replace("file:", "");
				
				// si queda alguna '/' más y es windows la quitamos, en linux no :-)
				if (targetPath.startsWith("/") && Os.isFamily(Os.OS_FAMILY_WINDOWS.getName())){
					targetPath = targetPath.substring(1, targetPath.length());
				}
			}
			
			// si no está encodeado no lo decodeamos
			targetPath =  (isURIEncoded(targetPath)?URIUtil.decode(targetPath, "utf-8"):targetPath);
			
		} catch (URIException e) {
			e.printStackTrace();
		}
		return targetPath;
	}
	
	public static String normalizarBarras(String path){
		return path.replaceAll("\\\\", "/");
	}
	
	public static boolean isURIEncoded(String path) {
		if (path.contains("%")) {
			
			try {
				/*
				 * 
				 * 1. miramos si el % es de un url-encode, o si es un caracter invalido en un path no normalizado
				 * 
				 * TODO este metodo hay que mejorarlo
				 *  ej: /home/irune/Escritorio/Pláéí  ñ _ ñ %C3%A1_%C3%B1o%256_&%C3%B1%C3%B1=.pdf (no encoded)
				 *      /hoome/irune/Escritorio/Pl%C3%A1_%C3%B1o%256_&%C3%B1%C3%B1=.pdf           (no encoded)
				 *      /home/irune/Escritorio/Plá_ño%6_&ññ=.pdf                                  (no encoded)  
				 *      C:/Documents%20and%20Settings/Administrador/Escritorio/dir%20%C3%A1%C3%A9%C3%AD%C3%B3%C3%BA%20%C3%B1_%60%C3%B1/Fillable_PDF_Sample_from_TheWebJockeys_vC5.pdf (encoded)
				 *      
				 *  ++ tiene que funcionar también para cuando se entra con la URIEncodeada cuando el resultado inicial fue 'no encoded'
				 *   y detectar que ahora si lo esta (en la segunda vuelta, una vez encodeado lo no encodeado)                              
				 *  
				 *  
				 *  Tal y como lo dejo, 
				 */
				
				// 
				URLDecoder.decode(path, "utf-8");
				return true;
				
			/*
			 * java.lang.IllegalArgumentException: 
			 * URLDecoder: Illegal hex characters in escape (%) pattern - For input string: "6_"	
			 */
			} catch (Exception e) {
				return false;
			}
		} else {
			return false;
		}
	}
	
	private static URI normalizarURI(String filePath) throws UnsupportedEncodingException, URISyntaxException, URIException{

		// normalización windows
		filePath = normalizarBarras(filePath);
					
		// si está encodeado no lo reencodeamos
		String encodedFilePath =  (isURIEncoded(filePath)?filePath:URIEncoder.encode(filePath, "utf-8"));
		
		// pasamos de utf-8 a latin1
		String decoded = URLDecoder.decode(encodedFilePath, "utf-8");
		encodedFilePath = URIUtil.encodePath(decoded, "iso-8859-1");
		
		
		URI fileURI = new URI(encodedFilePath);
		String protocol = fileURI.getScheme();
		if (protocol != null && protocol.equalsIgnoreCase("sinadura")) {
			fileURI = new URI(encodedFilePath.replace("sinadura://", "webdav://"));
		} else if (protocol != null && protocol.equalsIgnoreCase("sinaduras")) {
			fileURI = new URI(encodedFilePath.replace("sinaduras://", "webdavs://"));
		}
		return fileURI;
	}
	
	
	public static boolean isFile(String fileUri) throws FileSystemException
	{
		return !isDirectory(fileUri);
	}
	
	
	public static boolean isDirectory(String fileUri) throws FileSystemException
	{
		return false;
//		FileSystemManager fsManager = VFS.getManager();
//		FileObject parentFolder = fsManager.resolveFile(getParentFolder(fileUri));
//		FileObject file;
//		if(getFileName(fileUri).length() > 0)
//		{
//			file = parentFolder.resolveFile(getFileName(fileUri));
//		}
//		else
//		{
//			file = parentFolder;
//		}
//		if(file.getType() == FileType.FILE) //no se pilla el tipo de documento...
//		{
//			return false;
//		}
//		else
//		{
//			return true;
//		}
	}
	
	
	private static void TestConversion(String path) throws URISyntaxException{
		System.out.println(path);
		path = FileUtil.normaliceLocalURI(path);
		System.out.println(path);
		// importante usar java.net.URI y no de otra paquetería, ya que si no //chronos/... suele fallar =I
		URI uri = new URI(path);
//		System.out.println(uri.getScheme());
		System.out.println(uri.toString());
//		System.out.println();
		
	}
	public static void main(String[] args) throws URISyntaxException{

		String path = new String("C:/Archivos de programa/Plá_ño%6_&ññ=.pdf");
		boolean encoded = FileUtil.isURIEncoded(path);
		System.out.println(encoded);
		
		// pruebas con "new File(url.getFile()).toURI()"
//		URL url;
//		try {
//			url = new URL("file://" + "/home/alfredo/Escritorio/firmas-prod/ampliacion plazo varias justicia [1].sar");
//			System.out.println(new File(url.getFile()).toURI());
//		} catch (MalformedURLException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		
		FileUtil.TestConversion("/home/alfredo/Escritorio/firmas-prod/ampliacion plazo varias justicia[1].sar");
		FileUtil.TestConversion("\\\\192.168.1.61\\share\\dir_con_ficheros\\extrá\\pdf áéíóúñ_ñ.pdf");
		FileUtil.TestConversion("\\\\CHRONOS\\share\\dir_con_ficheros\\extrá\\pdf áéíóúñ_ñ.pdf");
		FileUtil.TestConversion("Z:\\dir_con_ficheros\\extrá\\pdf áéíóúñ_ñ.pdf");
		FileUtil.TestConversion("webdav://ipa001:123456@alf.zylk.net:8080/alfresco/webdav/webdav/Zylk/Guest/irune/sinadura webdav test áéióúñ_ñ/pdf con espacios-signed.pdf");
		FileUtil.TestConversion("sinadura://ipa001:123456@alf.zylk.net:8080/alfresco/webdav/webdav/Zylk/Guest/irune/sinadura webdav test áéióúñ_ñ/pdf con espacios-signed.pdf");
		FileUtil.TestConversion("/home/irune/Escritorio/sinadura dir con ficherós/extra/pdf áéíóúñ_ñ.pdf");
		FileUtil.TestConversion("C:\\Documents and Settings\\Administrador\\Escritorio\\dir con ficheros\\extrá\\pdf áéíóú ñ_ñ.pdf");
		FileUtil.TestConversion("file:///C:\\Documents and Settings\\Administrador\\Escritorio\\dir con ficheros\\extrá\\pdf áéíóú ñ_ñ.pdf");
		FileUtil.TestConversion("file:////home/irune/Escritorio/sinadura dir con ficherós/extra/pdf áéíóúñ_ñ.pdf");
	}
}
