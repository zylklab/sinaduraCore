package net.esle.sinadura.core.validate;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import net.esle.sinadura.core.exceptions.DigidocException;
import net.esle.sinadura.core.model.DataFile;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;


public class DigidocUtil {


	public static List<DataFile> getDataFiles(String xmlPath) throws DigidocException {
		
		try {
			List<DataFile> listaValues = new ArrayList<DataFile>();
	
			DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = domFactory.newDocumentBuilder();
			
			InputStream is = new FileInputStream(new File(xmlPath));
			Reader reader = new InputStreamReader(is, "UTF-8");
			
			InputSource source = new InputSource(reader);
			source.setEncoding("UTF-8");
			Document doc = builder.parse(source);
	
			XPathFactory factory = XPathFactory.newInstance();
			XPath xpath = factory.newXPath();
			XPathExpression expr = xpath.compile("//SignedDoc/DataFile");
			Object result = expr.evaluate(doc, XPathConstants.NODESET);
			
			NodeList nodes = (NodeList) result;
			for (int i = 0; i < nodes.getLength(); i++) {
				
				Node node = nodes.item(i);
				DataFile dataFile = new DataFile();
				dataFile.setDigestType(node.getAttributes().getNamedItem("DigestType").getNodeValue());
				dataFile.setDigestValue(node.getAttributes().getNamedItem("DigestValue").getNodeValue());
				dataFile.setFilename(node.getAttributes().getNamedItem("Filename").getNodeValue());
				listaValues.add(dataFile);
			}
			
			return listaValues;
			
		} catch (IOException e) {
			throw new DigidocException(e);
		} catch (ParserConfigurationException e) {
			throw new DigidocException(e);
		} catch (SAXException e) {
			throw new DigidocException(e);
		} catch (XPathExpressionException e) {
			throw new DigidocException(e);
		}
		
	}
	
}