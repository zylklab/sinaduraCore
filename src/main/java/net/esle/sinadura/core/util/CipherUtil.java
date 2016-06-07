package net.esle.sinadura.core.util;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import net.esle.sinadura.core.exceptions.CipherException;

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;

/**
 * Esta clase tal y como esta implementada es practicamente un util del Desktop.
 * 
 * La key esta hardcode porque unicamente es un sistema de ofuscacion.
 * 
 */
public class CipherUtil {

	private static final String keyString = "sinadura";

	private static SecretKey getKey() throws CipherException {

		try {
			// only the first 8 Bytes of the constructor argument are used
			// as material for generating the keySpec
			DESKeySpec keySpec = new DESKeySpec(keyString.getBytes("UTF8"));
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			SecretKey key = keyFactory.generateSecret(keySpec);

			return key;

		} catch (InvalidKeyException e) {
			throw new CipherException(e);
		} catch (UnsupportedEncodingException e) {
			throw new CipherException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new CipherException(e);
		} catch (InvalidKeySpecException e) {
			throw new CipherException(e);
		}
	}

	public static String encrypt(String data) throws CipherException {

		try {
			SecretKey key = getKey();
			byte[] cleartext = data.getBytes("UTF8");
			Cipher cipher = Cipher.getInstance("DES"); // cipher is not thread safe
			cipher.init(Cipher.ENCRYPT_MODE, key);
			String encrypedPwd = Base64.encode(cipher.doFinal(cleartext));

			return encrypedPwd;

		} catch (UnsupportedEncodingException e) {
			throw new CipherException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new CipherException(e);
		} catch (NoSuchPaddingException e) {
			throw new CipherException(e);
		} catch (InvalidKeyException e) {
			throw new CipherException(e);
		} catch (IllegalBlockSizeException e) {
			throw new CipherException(e);
		} catch (BadPaddingException e) {
			throw new CipherException(e);
		}
	}

	public static String decrypt(String data) throws CipherException {

		try {
			SecretKey key = getKey();
			byte[] encrypedPwdBytes = Base64.decode(data);
			Cipher cipher = Cipher.getInstance("DES");// cipher is not thread safe
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] plainTextPwdBytes = (cipher.doFinal(encrypedPwdBytes));
			
			return new String(plainTextPwdBytes, "UTF8");
			
		} catch (Base64DecodingException e) {
			throw new CipherException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new CipherException(e);
		} catch (NoSuchPaddingException e) {
			throw new CipherException(e);
		} catch (InvalidKeyException e) {
			throw new CipherException(e);
		} catch (IllegalBlockSizeException e) {
			throw new CipherException(e);
		} catch (BadPaddingException e) {
			throw new CipherException(e);
		} catch (UnsupportedEncodingException e) {
			throw new CipherException(e);
		}
	}

	public static void main(String[] args) throws Exception {
		
		String encrypt = CipherUtil.encrypt("1111");
		System.out.println("encrypt: " + encrypt);
		String password = CipherUtil.decrypt(encrypt);
		System.out.println("decrypt: " + password);
		
	}
	
}
