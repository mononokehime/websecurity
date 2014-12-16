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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;


/**
 * Implementation of EnhancedSecurityModelKeyExchange
 *
 * @author MacDermotF
 */
public class EnhancedSecurityModelKeyExchangeImpl implements EnhancedSecurityModelKeyExchange {

	/**
	 * {@inheritDoc}
	 */
	@Override
	public EnhancedSecuritySessionKeys createSessionKeys(final String sMKComponent, final String sEKComponent,
			final String aliasName) throws NoSuchAlgorithmException, InvalidKeySpecException {

		keys.setServerSEKComponent(Hex.encodeHexString(serverSEKComponent));
		keys.setServerSMKComponent(Hex.encodeHexString(serverSMKComponent));
		return keys;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Key createSEK(final byte[] serverSEKComponent, final String sEKComponent, final String aliasName)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		return combineKeyComponents(serverSEKComponent, sEKComponent, EnhancedSecurityModelKeyExchange.AES, aliasName);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Key createSMK(final byte[] serverSMKComponent, final String clientSMKComponent, String aliasName)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		return combineKeyComponents(serverSMKComponent, clientSMKComponent,
			EnhancedSecurityModelKeyExchange.HMAC_SHA256_ALGORITHM, aliasName);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] generateMACKeyComponent() throws NoSuchAlgorithmException {
		final KeyGenerator keyGenerator = getKeyGenerator(HMAC_SHA256_ALGORITHM, 256);
		final SecretKey keyComponent = keyGenerator.generateKey();
		return keyComponent.getEncoded();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] generateEncryptionKeyComponent() throws NoSuchAlgorithmException {
		final KeyGenerator keyGenerator = getKeyGenerator(AES, 128);
		final SecretKey keyComponent = keyGenerator.generateKey();
		return keyComponent.getEncoded();
	}

	private Key combineKeyComponents(byte[] serverComponent, String clientComponent, String keyAlgorithm,
			String aliasName) throws NoSuchAlgorithmException, InvalidKeySpecException {


		return new SecretKeySpec(out, keyAlgorithm);
	}

	private KeyGenerator getKeyGenerator(String algorithm, int keysize) throws NoSuchAlgorithmException {
		final KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		keyGenerator.init(keysize, new SecureRandom());
		return keyGenerator;
	}

	private byte[] decryptKeyComponent(byte[] keyComponent, String version) {

		return decryptBytes(cipher, keyComponent);
	}

	private byte[] decryptBytes(javax.crypto.Cipher cipher, byte[] data) {
		try {
			return cipher.doFinal(data);
		} catch (IllegalBlockSizeException e) {
			throw new IllegalArgumentException(e);
		} catch (BadPaddingException e) {
			throw new IllegalArgumentException(e);
		}
	}

	private Cipher getCipher(String algorithm) {
		try {
			return javax.crypto.Cipher.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(e);
		} catch (NoSuchPaddingException e) {
			throw new IllegalArgumentException(e);
		}

	}

	/*
	 * The prefix for looking up the server private key alias from the JVM args
	 */
	private final String privateKeyAliasKeyPrefix = "esm.alias.";
}
