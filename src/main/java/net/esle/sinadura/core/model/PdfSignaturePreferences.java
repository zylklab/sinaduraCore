package net.esle.sinadura.core.model;

import com.itextpdf.text.Image;
import com.itextpdf.text.pdf.PdfSignatureAppearance;


/**
 * @author alfredo
 */
public class PdfSignaturePreferences extends SignaturePreferences {
	
	
	private boolean visible = false;
	private String acroField = null;
			
	private int page = 1;
	private float startX = 0;
	private float startY = 0;
	private float widht = 0;
	private float height = 0;
	
	private String reason = null;
	private String location = null;
	
	private Image image = null;
	private int certified = PdfSignatureAppearance.NOT_CERTIFIED;
	
	
	public PdfSignaturePreferences() {	
	}
	
	public void setVisible(boolean visible) {
		this.visible = visible;
	}
	public boolean getVisible() {
		return visible;
	}
	public void setReason(String reason) {
		this.reason = reason;
	}
	public String getReason() {
		return reason;
	}
	public void setLocation(String location) {
		this.location = location;
	}
	public String getLocation() {
		return location;
	}
	public void setStartX(float startX) {
		this.startX = startX;
	}
	public float getStartX() {
		return startX;
	}
	public void setStartY(float startY) {
		this.startY = startY;
	}
	public float getStartY() {
		return startY;
	}
	public void setWidht(float widht) {
		this.widht = widht;
	}
	public float getWidht() {
		return widht;
	}
	public void setHeight(float height) {
		this.height = height;
	}
	public float getHeight() {
		return height;
	}
	public void setCertified(int certified) {
		this.certified = certified;
	}
	public int getCertified() {
		return certified;
	}
	public void setImage(Image image) {
		this.image = image;
	}
	public Image getImage() {
		return image;
	}
	public void setPage(int page) {
		this.page = page;
	}
	public int getPage() {
		return page;
	}
	public String getAcroField() {
		return acroField;
	}
	public void setAcroField(String acroField) {
		this.acroField = acroField;
	}

}
