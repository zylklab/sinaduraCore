package net.esle.sinadura.core;

import net.esle.sinadura.core.service.XadesService;


public class XadesTest {
	
	
	public static void main(String[] args) {

	    // carga por classpath
//		String PKCS12_RESOURCE = "/net/esle/sinadura/core/resources/cert_entidad_software_des.p12";
		String PKCS12_RESOURCE = "/home/alfredo/workspaces/sinadura3/sinaduraCore/src/net/esle/sinadura/core/resources/cert_entidad_software_des.p12";
	    String PKCS12_PASSWORD = "1111";
	    
	    String OUTPUT_DIRECTORY = "/home/alfredo/Escritorio";
	    String SIGN_FILE_NAME = "XAdES-BES-Sign.xml";
	    
	    // carga por classpath
//	    String RESOURCE_TO_SIGN = "/net/else/sinadura/core/resources/ExampleToSign.xml";
	    String RESOURCE_TO_SIGN = "/home/alfredo/workspaces/sinadura3/sinaduraCore/src/net/esle/sinadura/core/resources/ExampleToSign.xml";
	    
//		XadesService.signXadesBes(PKCS12_RESOURCE, PKCS12_PASSWORD, OUTPUT_DIRECTORY, RESOURCE_TO_SIGN, SIGN_FILE_NAME);
		
    }
}
