/*
 * MONITISE CONFIDENTIAL
 * ____________________
 *
 * Copyright 2003 - 2013 Monitise Group Limited
 * All Rights Reserved. www.monitisegroup.com
 *
 * NOTICE: All information contained herein is, and remains
 * the property of Monitise Group Limited or its group
 * companies. The intellectual and technical concepts contained
 * herein are proprietary to Monitise Group Limited and Monitise
 * group companies and may be covered by U.S. and
 * Foreign Patents, patents in process, and are protected by
 * trade secret or copyright law. Dissemination of this information
 * or reproduction of this material is strictly forbidden unless prior
 * written permission is obtained from Monitise Group Limited. Any
 * reproduction of this material must contain this notice
 *
 */
package com.monitise.ep.commons.cryptography;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for help with keystore operations.
 *
 * @author MacDermotF
 */
public final class KeyStoreUtil {

	private static final KeyStoreUtil KEY_STORE_UTIL = new KeyStoreUtil();

	private KeyStoreUtil() {
	}

	/**
	 * @return the KeyStoreUtil singleton.
	 */
	public static KeyStoreUtil getInstance() {
		return KEY_STORE_UTIL;
	}

	/**
	 * Obtains the server private key for the alias provided
	 *
	 * @param aliasName the alias name for the server private key
	 * @return the private key
	 * @throws IOException when unable to read the keystore
	 */
	public PrivateKey getPrivateKey(String aliasName) throws IOException {
		KeyStore keyStore;
		try {
			keyStore = getKeyStore(System.getProperty(keyStoreKey), System.getProperty(keyStorePasswordKey),
				KeyStore.getDefaultType(), null);
		} catch (KeyStoreException e) {
			throw new IOException(e);
		} catch (NoSuchProviderException e) {
			throw new IOException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		} catch (CertificateException e) {
			throw new IOException(e);
		}

		Key key;
		try {
			key = keyStore.getKey(aliasName, System.getProperty(keyStorePasswordKey).toCharArray());
		} catch (UnrecoverableKeyException e) {
			throw new IOException(e);
		} catch (KeyStoreException e) {
			throw new IOException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}

		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}

		RSAPrivateCrtKeySpec pkSpec;
		try {
			pkSpec = keyFactory.getKeySpec(key, RSAPrivateCrtKeySpec.class);
		} catch (InvalidKeySpecException e) {
			throw new IOException(e);
		}
		try {
			return keyFactory.generatePrivate(pkSpec);
		} catch (InvalidKeySpecException e) {
			throw new IOException(e);
		}
	}

	/**
	 * Loads a keystore for the given filename. Looks for the filename firstly on the classpath and the using an
	 * absolute file name.
	 *
	 * @param filename the keystore for the KeyStore, either a classname or file name.
	 * @param passphrase the keystore passphrase.
	 * @param type keystore type
	 * @param provider keystore provider
	 * @return the KeyStore
	 * @throws KeyStoreException an error occurred loading the keystore
	 * @throws NoSuchProviderException the provider name is invalid
	 * @throws IOException the keystore could not be loaded
	 * @throws NoSuchAlgorithmException a required algorithm could not be found
	 * @throws CertificateException an error occurred loading the keystore
	 */
	public KeyStore getKeyStore(String filename, String passphrase, String type, String provider)
			throws KeyStoreException, NoSuchProviderException, IOException, NoSuchAlgorithmException,
			CertificateException {
		InputStream is = null;
		try {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Loading keystore from " + filename);
			}
			KeyStore keystore;
			if (provider == null) {
				keystore = KeyStore.getInstance(type);
			} else {
				keystore = KeyStore.getInstance(type, provider);
			}

			// try to load the filename from the classpath and if that fails just open
			// the filename directly
			is = getClass().getClassLoader().getResourceAsStream(filename);
			if (is == null) {
				is = new FileInputStream(filename);
			}
			keystore.load(is, passphrase.toCharArray());

			if (LOG.isDebugEnabled()) {
				LOG.debug("Keystore loaded from " + filename);
			}
			return keystore;
		} finally {
			if (is != null) {
				is.close();
			}
		}
	}

	private static final Logger LOG = LoggerFactory.getLogger(KeyStoreUtil.class);
	private final String keyStoreKey = "javax.net.ssl.keyStore";
	private final String keyStorePasswordKey = "javax.net.ssl.keyStorePassword";
}
