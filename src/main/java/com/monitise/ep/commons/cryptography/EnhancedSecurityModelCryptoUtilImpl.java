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

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Implementation of EnhancedSecurityModelCryptoUtil
 *
 * @author MacDermotF
 */
public class EnhancedSecurityModelCryptoUtilImpl implements EnhancedSecurityModelCryptoUtil {
	private static final int IV_LENGTH = 16; // 16 bytes = 128 bits
	private static final Logger LOG = LoggerFactory.getLogger(EnhancedSecurityModelCryptoUtilImpl.class);
	/*
	 * Used for random byte generation for the IV
	 */
	private final SecureRandom ranGen = new SecureRandom();

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] encryptData(final Key key, final IvParameterSpec iv, final byte[] data) {
		Assert.notNull(key, "SEK cannot be empty");
		Assert.notNull(iv, "IV cannot be empty");
		final byte[] encryptedData = new byte[0];
		// need a new IV for this

		if (data != null && data.length > 0) {
			return processData(key, iv, data, true);
		}
		return encryptedData;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] decryptData(final Key key, final byte[] iv, final byte[] data) {
		Assert.notNull(key, "SEK cannot be empty");
		Assert.notNull(iv, "IV cannot be empty");
		if (LOG.isDebugEnabled()) {
			LOG.debug("IV for decrypt is:" + iv.length);
		}
		final byte[] decryptedData = processData(key, convertByteToIV(iv), data, false);
		return decryptedData;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String calculateHMAC(final Key key, final byte[] data) {
		final Mac mac;
		try {
			mac = Mac.getInstance(EnhancedSecurityModelKeyExchange.HMAC_SHA256_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(e);
		}
		try {
			mac.init(key);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean areMACValuesEqual(final Key key, final byte[] data, final String mac) {
		final String internalMAC = calculateHMAC(key, data);
		if (LOG.isDebugEnabled()) {
			LOG.debug("Comparing internalMAC [" + internalMAC + "] with external mac [" + mac + "]");
		}
		return mac.equals(internalMAC);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public IvParameterSpec generateIV() {

		return new javax.crypto.spec.IvParameterSpec(iV);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public IvParameterSpec convertByteToIV(final byte[] iv) {
		return new javax.crypto.spec.IvParameterSpec(iv);
	}

	private byte[] processData(Key sek, IvParameterSpec iv, byte[] data, boolean encrypt) {
		if (data == null || data.length < 1) {
			return data;
		}
		final javax.crypto.Cipher cipher;

	}

}
