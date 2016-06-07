package net.esle.sinadura.core.keystore;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.lang.reflect.Method;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.ocsp.CertificateStatus;

import net.esle.sinadura.core.exceptions.CoreException;

import sun.security.pkcs11.wrapper.CK_SLOT_INFO;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class PKCS11Helper {

	private static final Log log = LogFactory.getLog(KeyStoreBuilderFactory.class);

	private static int MAX_CERTS = 1000;
	private static long CKM_RSA_PKCS = 0x00000001;
	private static long CKM_SHA1_RSA_PKCS = 0x00000006;

	String _initArgs, _pk11LibPath, _name;
	Vector<X509Certificate> certificates = new Vector<X509Certificate>();

	public HashMap<String, X509Certificate> certificateBySlots = new HashMap<String, X509Certificate>();

	PKCS11 p11 = null;

	public PKCS11Helper(String pk11LibPath, String initArgs) throws CoreException {

		_initArgs = initArgs;
		_pk11LibPath = pk11LibPath;
		initialize();
	}

	public PKCS11Helper(String pk11LibPath) throws CoreException {

		_initArgs = null;
		_pk11LibPath = pk11LibPath;
		initialize();

	}

	public String getName() {
		return _name;
	}

	private void initialize() throws CoreException {

		long hSession = 0;
		long[] slots;
		boolean found = false;

		CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[1];
		CK_ATTRIBUTE attr = new CK_ATTRIBUTE();
		CK_TOKEN_INFO ckti = null;

		p11 = getP11Instance();

		try {
			slots = p11.C_GetSlotList(true); // true is token present, false to
												// get all slots.
		} catch (Exception e) {
			// throw new CoreException("Getting Slot List::"
			// + e.getMessage(),
			// PKCS11HelperException.errorType.ERR_GET_SLOT_LIST);
			throw new CoreException(e);
		}

		for (long k : slots) {

			try {
				for (long x : p11.C_GetMechanismList(k)) {
					if (x == CKM_RSA_PKCS || x == CKM_SHA1_RSA_PKCS) {
						log.debug("Slot " + k + " has signature capabilities");
						break;
					}
				}
				ckti = p11.C_GetTokenInfo(k);
				_name = new String(ckti.label);
			} catch (Exception e) {
				// throw new PKCS11HelperException("Getting token Info::"
				// + e.getMessage(),
				// PKCS11HelperException.errorType.ERR_GET_TOKEN_INFO);

				new CoreException(e);
			}

			try {
				hSession = p11.C_OpenSession(k, PKCS11Constants.CKF_SERIAL_SESSION, null, null);
			} catch (Exception e) {
				// throw new PKCS11HelperException("Opening a new Session::"
				// + e.getMessage(),
				// PKCS11HelperException.errorType.ERR_OPEN_SESSION);
				new CoreException(e);
			}

			attr.type = PKCS11Constants.CKA_CLASS;
			attr.pValue = PKCS11Constants.CKO_CERTIFICATE;
			attrs[0] = attr;

			try {
				p11.C_FindObjectsInit(hSession, attrs);

				long[] l = p11.C_FindObjects(hSession, MAX_CERTS);

				p11.C_FindObjectsFinal(hSession);

				for (long i : l) {

					

					CK_ATTRIBUTE attrPriv = new CK_ATTRIBUTE();
					CK_ATTRIBUTE[] attrsP = new CK_ATTRIBUTE[2];

					attrPriv.type = PKCS11Constants.CKA_CLASS;
					attrPriv.pValue = PKCS11Constants.CKA_PRIVATE;// CKO_PRIVATE_KEY;

					attr.type = PKCS11Constants.CKA_ID;
					attr.pValue = getID(hSession, i, p11);

					if (attr.pValue != null) {
						attrsP[0] = attrPriv;
						attrsP[1] = attr;

						p11.C_FindObjectsInit(hSession, attrsP);
						long[] m = p11.C_FindObjects(hSession, MAX_CERTS);
						if (m.length > 0) {
							found = true;
							certificates.add(loadCert(hSession, i, p11));
							certificateBySlots.put(k + "," + i, loadCert(hSession, i, p11));
						}
						p11.C_FindObjectsFinal(hSession);
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
				// throw new PKCS11HelperException(
				// "Unsuccesfully FindObjects secuence::" + e.getMessage(),
				// PKCS11HelperException.errorType.ERR_FIND_OBJECTS);
				new CoreException(e);
			}

			try {
				p11.C_CloseSession(hSession);
				// if (found) //no lo quiero parar ya que necesito todos los que estén en los slots
				// break;
			} catch (Throwable e) {
				// throw new PKCS11HelperException("Cannot close sesion::"
				// + e.getMessage(),
				// PKCS11HelperException.errorType.ERR_CLOSE_SESSION);
				e.printStackTrace();
			}
		}

		try {
			// Should be revised against the code of jdk.
			// That should be done under normal conditions, but when using
			// com.sun.security classes,
			// something happen that make future SunPKCS11 provider against
			// mozilla library
			// fails on session handle.

			// p11.C_Finalize(hSession);

			p11 = null;
			Runtime.getRuntime().gc();
		} catch (Throwable e) {
			// throw new PKCS11HelperException("Cannot Finalize::"
			// + e.getMessage(),
			// PKCS11HelperException.errorType.ERR_FINALIZE);
			e.printStackTrace();
		}
	}

	private X509Certificate loadCert(long session, long oHandle, PKCS11 p11) throws PKCS11Exception, CertificateException {

		CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[] { new CK_ATTRIBUTE(PKCS11Constants.CKA_VALUE) };
		p11.C_GetAttributeValue(session, oHandle, attrs);

		byte[] bytes = attrs[0].getByteArray();
		if (bytes == null) {
			throw new CertificateException("unexpectedly retrieved null byte array");
		}
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
	}

	private byte[] getID(long session, long oHandle, PKCS11 p11) throws PKCS11Exception, CertificateException {

		byte[] bytes = null;
		CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[] { new CK_ATTRIBUTE(PKCS11Constants.CKA_ID) };

		p11.C_GetAttributeValue(session, oHandle, attrs);

		if (attrs[0].pValue != null) {
			bytes = attrs[0].getByteArray();
		}

		return bytes;
	}

	public X509Certificate[] getCertificates() throws CoreException {
		X509Certificate[] xcer = new X509Certificate[0];
		return certificates.toArray(xcer);
	}

	public long[] getSignatureCapableSlots() throws CoreException {

		long[] slots;

		Vector<Long> vslots = new Vector<Long>();

		p11 = getP11Instance();

		try {
			slots = p11.C_GetSlotList(true); // true is token present, false to
												// get all slots.
		} catch (Exception e) {
			// throw new PKCS11HelperException("Getting Slot List::"
			// + e.getMessage(),
			// PKCS11HelperException.errorType.ERR_GET_SLOT_LIST);
			throw new CoreException(e);
		}

		for (long k : slots) {
			try {
				for (long x : p11.C_GetMechanismList(k)) {
					if (x == CKM_SHA1_RSA_PKCS) {
						vslots.add(k);
						break;
					}
				}
			} catch (PKCS11Exception e) {
				// throw new PKCS11HelperException("Cannot get Mechanism list::"
				// + e.getMessage(),
				// PKCS11HelperException.errorType.ERR_GET_SLOT_LIST);
				throw new CoreException(e);
			}
		}

		long[] res = new long[vslots.size()];
		for (int i = 0; i < vslots.size(); i++) {
			res[i] = vslots.get(i);
		}

		return res;
	}

	public PKCS11 getP11Instance() throws CoreException {

		Method[] methods = PKCS11.class.getMethods();
		Method p11Getinstance = null;
		PKCS11 p11 = null;

		CK_C_INITIALIZE_ARGS cia = new CK_C_INITIALIZE_ARGS();

		cia.pReserved = (Object) _initArgs;
		cia.flags = 0;

		for (int i = 0; i < methods.length; i++) {
			if (methods[i].getName().equals("getInstance"))
				p11Getinstance = methods[i];
		}
		try {
			File _fpk11LibPath = new File(_pk11LibPath);
			_pk11LibPath = _fpk11LibPath.getCanonicalPath();
			String version = System.getProperty("java.version");
			if (version.indexOf("1.6") > -1 || version.indexOf("1.7") > -1 || version.indexOf("1.8") > -1 || version.indexOf("1.9") > -1) {
				// JRE 1.6 , JRE 1.7, JRE 1.8, JRE 1.9
				p11 = (PKCS11) p11Getinstance.invoke(null, new Object[] { _pk11LibPath, "C_GetFunctionList", null, false });
			} else if (version.indexOf("1.5") > -1) {
				// JRE 1.5
				p11 = (PKCS11) p11Getinstance.invoke(null, new Object[] { _pk11LibPath, cia, false });
			} else {
				System.err.println("Unsupported version of VM");
				return null;// System.exit(-1);
			}
		} catch (Exception e) {
			e.printStackTrace();
			// throw new PKCS11HelperException(
			// "Problem using java reflection with pkcs11 classes::"
			// + e.getMessage(),
			// PKCS11HelperException.errorType.ERR_INVOKE_INITIALIZE);
			throw new CoreException(e);
		}

		return p11;
	}

	public HashMap<String, Long> getSoltsByReaderName() throws CoreException {
		HashMap<String, Long> a = new HashMap<String, Long>();
		long[] slots = this.getSignatureCapableSlots();
		for (long l : slots) {
			try {
				char[] label = this.p11.C_GetTokenInfo(l).label;
				char[] slotLInfo = this.p11.C_GetSlotInfo(l).slotDescription;
				String sl = new String(label);
				String si = new String(slotLInfo);

				sl = sl.trim();
				si = si.trim();

				a.put(si + " " + sl + " (" + l + ")", l);

				// p11.C_Finalize(this.p11.C_GetSlotInfo(l));
				// p11.C_Finalize(this.p11.C_GetTokenInfo(l));

			} catch (PKCS11Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				throw new CoreException(e);
			}
		}

		return a;
	}

	public static void main(String[] args) throws CoreException, PKCS11Exception {
		PKCS11Helper pk11h = new PKCS11Helper("/usr/lib/opensc-pkcs11.so", "");

		// for (X509Certificate xc : pk11h.getCertificates()) {
		// System.out.println("------------------->"+xc.getSubjectDN());
		// }

		HashMap<String, X509Certificate> ss = pk11h.certificateBySlots;

		Set<String> s = ss.keySet();
		for (String string : s) {
			System.out.println("------------------->" + ss.get(string).getSubjectDN());
		}

		// Lets try to get slots by a given mechanism:
		for (long i : pk11h.getSignatureCapableSlots()) {
			System.out.println("\n\nSlot " + i + " is signature capable.");
			CK_SLOT_INFO c = pk11h.p11.C_GetSlotInfo(i);
			System.out.println("Slot " + i + " INFO " + c.toString());
			System.out.println("Slot " + i + " INFO " + c.slotDescription);
			System.out.println("Slot " + i + " INFO " + c.manufacturerID);
		}

	}
}
