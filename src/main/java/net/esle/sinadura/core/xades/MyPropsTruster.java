
package net.esle.sinadura.core.xades;

import es.mityc.javasign.trust.PropsTruster;
import es.mityc.javasign.trust.TrustAdapter;

/**
 * <p>Gestiona las entidades de confianza que admite MITyC.</p>
 * <p>Esta clase se basa en ficheros de configuración para parametrizar los certificados admitidos (en /trust/mitycsimple.properties).</p>
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class MyPropsTruster extends PropsTruster {

	/** Fichero de configuración. */
	private static final String CONF_FILE = "trust/mytruster.properties";

	/**
	 * <p>Constructor.</p>
	 * @param fileconf
	 */
	private MyPropsTruster() {
		super(CONF_FILE);
	}

	/**
	 * <p>Devuelve una instancia única del gestionador de confianza del MITyC.</p>
	 * @return Instancia de este gestionador de confianza
	 */
	public static TrustAdapter getInstance() {
		if (instance == null) {
			instance = new MyPropsTruster();
		}
		return instance;
	}
}
