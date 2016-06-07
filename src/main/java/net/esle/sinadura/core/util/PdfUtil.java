package net.esle.sinadura.core.util;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore.PasswordProtection;
import java.util.ArrayList;
import java.util.List;

import javax.imageio.ImageIO;

import net.esle.sinadura.core.model.PdfSignatureField;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;

import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.AcroFields.FieldPosition;
import com.itextpdf.text.pdf.PdfReader;

public class PdfUtil {

	private static Log log = LogFactory.getLog(PdfUtil.class);

	
	public static int getNumberOfPages(InputStream is, PasswordProtection pwdProtection) throws IOException {
		
		return getNumberOfPages(is, null, pwdProtection);
	}
	
	public static int getNumberOfPages(String inputPath, PasswordProtection pwdProtection) throws IOException {
	
		return getNumberOfPages(null, inputPath, pwdProtection);
	}
	
	
	public static int getNumberOfPages(InputStream is, String inputPath, PasswordProtection pwdProtection) throws IOException {
		
		// pdfs protegidos
		byte[] ownerPassword = null;
		if ((pwdProtection != null) && (pwdProtection.getPassword() != null)) {
			ownerPassword = new String(pwdProtection.getPassword()).getBytes();
		}
		
		PdfReader reader;
		if (inputPath != null) {
			reader = new PdfReader(inputPath, ownerPassword);
		} else {
			reader = new PdfReader(is, ownerPassword);
		}
		
		int numberOfPages = reader.getNumberOfPages();
		
		reader.close();
		
		return numberOfPages;
	}
	
	
	
	/**
	 * @param is
	 * @param os
	 * @param page comienza en 1
	 * @throws IOException 
	 */
	public static void getPageImage(InputStream is, OutputStream os, int page) throws IOException {

		PDDocument doc = PDDocument.load(is);
		PDPage firstPage = (PDPage) doc.getDocumentCatalog().getAllPages().get(page - 1);
		
		BufferedImage bufferedImage = firstPage.convertToImage(BufferedImage.TYPE_INT_RGB, 52);
		
		ImageIO.write(bufferedImage, "png", os);
		
		doc.close();
	}
	
	
	public static List<PdfSignatureField> getBlankSignatureFields(String inputPath, PasswordProtection pwdProtection) throws IOException {

		return getBlankSignatureFields(null, inputPath, pwdProtection);
	}

	public static List<PdfSignatureField> getBlankSignatureFields(InputStream is, PasswordProtection pwdProtection) throws IOException {

		return getBlankSignatureFields(is, null, pwdProtection);
	}


	private static List<PdfSignatureField> getBlankSignatureFields(InputStream is, String inputPath, PasswordProtection pwdProtection) throws IOException {

		List<PdfSignatureField> pdfBlankSignatureFields = new ArrayList<PdfSignatureField>();
		
		// pdfs protegidos
		byte[] ownerPassword = null;
		if ((pwdProtection != null) && (pwdProtection.getPassword() != null)) {
			ownerPassword = new String(pwdProtection.getPassword()).getBytes();
		}
		
		PdfReader reader;
		if (inputPath != null) {
			reader = new PdfReader(inputPath, ownerPassword);
		} else {
			reader = new PdfReader(is, ownerPassword);
		}
		
		// nombre del signature field del docu de test: "_OPT_Spar"
		AcroFields acroFields = reader.getAcroFields();
		List<String> blankSignatureNames = acroFields.getBlankSignatureNames();
		
		for (String blankSignatureName : blankSignatureNames) {
		
			List<FieldPosition> positions = reader.getAcroFields().getFieldPositions(blankSignatureName);
			
			Rectangle pageSize = reader.getPageSize(positions.get(0).page);
			
			PdfSignatureField pdfSignatureField = new PdfSignatureField();
			pdfSignatureField.setName(blankSignatureName);
			// conversion de cordenadas itext --> awt/swt
			pdfSignatureField.setStartX(positions.get(0).position.getLeft());
			pdfSignatureField.setStartY(pageSize.getHeight() - positions.get(0).position.getHeight() - positions.get(0).position.getBottom());
			pdfSignatureField.setWidht(positions.get(0).position.getWidth());
			pdfSignatureField.setHeight(positions.get(0).position.getHeight());			
			pdfSignatureField.setPage(positions.get(0).page);
			pdfBlankSignatureFields.add(pdfSignatureField);
		}

		return pdfBlankSignatureFields;
	}
	
	
	
}
