/*
 * # Copyright 2008 zylk.net # # This file is part of Sinadura. # # Sinadura is free software: you can redistribute it
 * and/or modify # it under the terms of the GNU General Public License as published by # the Free Software Foundation,
 * either version 2 of the License, or # (at your option) any later version. # # Sinadura is distributed in the hope
 * that it will be useful, # but WITHOUT ANY WARRANTY; without even the implied warranty of # MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the # GNU General Public License for more details. # # You should have received a copy
 * of the GNU General Public License # along with Sinadura. If not, see <http://www.gnu.org/licenses/>. [^] # # See
 * COPYRIGHT.txt for copyright notices and details. #
 */
package net.esle.sinadura.core.validate;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.SocketException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;

import net.esle.sinadura.core.exceptions.ConnectionException;
import net.esle.sinadura.core.exceptions.OCSPCoreException;
import net.esle.sinadura.core.exceptions.RevokedException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.CertificateStatus;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;



/**
 * @author zylk.net
 */
public class OcspUtil {
	
	private static final Log log = LogFactory.getLog(OcspUtil.class);

	public static byte[] getStatus(X509Certificate checkCert, X509Certificate rootCert, String url, Date date) throws RevokedException,
			OCSPCoreException, ConnectionException {
		
		try {
			log.info("revocation ocsp check: " + checkCert.getSubjectDN());
			log.info("url: " + url);
			
			OCSPReq request = generateOCSPRequest(rootCert, checkCert.getSerialNumber());
			byte[] array = request.getEncoded();
			URL urlt = new URL(url);
			HttpURLConnection con = (HttpURLConnection) urlt.openConnection();
			con.setConnectTimeout(5000);
			con.setRequestProperty("Content-Type", "application/ocsp-request");
			con.setRequestProperty("Accept", "application/ocsp-response");
			con.setDoOutput(true);
			OutputStream out = con.getOutputStream();
			DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
			dataOut.write(array);
			dataOut.flush();
			dataOut.close();
			
			log.info("http code: " + con.getResponseCode());
			
			if (con.getResponseCode() / 100 != 2) {
				throw new OCSPCoreException("respuesta http invalida. codigo: " + con.getResponseCode());
			}
			// Get Response
			InputStream in = (InputStream) con.getContent();
			OCSPResp ocspResponse = new OCSPResp(in);

			if (ocspResponse.getStatus() != 0) {
				throw new OCSPCoreException("estado invalido en la respuesta ocsp. status: " + ocspResponse.getStatus());
			}
			BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
			if (basicResponse != null) {
				SingleResp[] responses = basicResponse.getResponses();
				if (responses.length == 1) {
					SingleResp resp = responses[0];
					Object status = resp.getCertStatus();
					if (status == CertificateStatus.GOOD) {
						log.info("status good");
						return basicResponse.getEncoded();
					} else if (status instanceof org.bouncycastle.ocsp.RevokedStatus) {
						Date revocationTime = ((RevokedStatus)status).getRevocationTime();
						if (revocationTime.before(date)) {
							log.info("status revoked");
							throw new RevokedException();
						} else {
							log.info("status good (revoked after)");
							return basicResponse.getEncoded();
						}
					} else {
						throw new OCSPCoreException("ocsp response revocation status unknown");
					}
				}
			}
		} catch (IOException e) {
			if (e instanceof SocketException) {
				throw new ConnectionException(e);
			} else {
				throw new OCSPCoreException(e);
			}
		} catch (OCSPException e) {
			throw new OCSPCoreException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new OCSPCoreException(e);
		}
		return null;
	}
	
	private static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws OCSPException, IOException,
			NoSuchAlgorithmException {
		
		// Add provider BC
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		// Generate the id for the certificate we are looking for
		CertificateID id = new CertificateID(CertificateID.HASH_SHA1, issuerCert, serialNumber);

		// basic request generation with nonce
		OCSPReqGenerator gen = new OCSPReqGenerator();

		gen.addRequest(id);

		// create details for nonce extension
		Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
		Vector<X509Extension> values = new Vector<X509Extension>();

		oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
		values.add(new X509Extension(false, new DEROctetString(new DEROctetString(createDocumentId()).getEncoded())));

		gen.setRequestExtensions(new X509Extensions(oids, values));

		return gen.generate();
	}
	
	private static byte[] createDocumentId() throws NoSuchAlgorithmException {
		
		long seq = System.currentTimeMillis();
		
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		
		long time = System.currentTimeMillis();
		long mem = Runtime.getRuntime().freeMemory();
		String s = time + "+" + mem + "+" + (seq++);
		
		return md5.digest(s.getBytes());
	}

}
