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

import java.security.Key;

import javax.crypto.spec.IvParameterSpec;

/**
 * Class that provides utility methods for key exchange.
 *
 * @author MacDermotF
 */
public interface EnhancedSecurityModelCryptoUtil {

	/**
	 * Encrypts the supplied data using the key and iv supplied
	 *
	 * @param key the key for the encryption
	 * @param iV the IV to use
	 * @param data the data to encrypt
	 * @return the encrypted data
	 */
	byte[] encryptData(Key key, IvParameterSpec iV, byte[] data);

	/**
	 * Decrypts the supplied data
	 *
	 * @param key the key for the decryption
	 * @param iv the initialise vector
	 * @param data data the data to decrypt
	 * @return the decrypted data
	 */
	byte[] decryptData(Key key, final byte[] iv, byte[] data);

	/**
	 * Calculates an MAC based on the data provided
	 *
	 * @param key the key to MAC with
	 * @param data the data to MAC
	 * @return a Base64 encoded MAC
	 */
	String calculateHMAC(Key key, byte[] data);

	/**
	 * Compares two MAC values for equality with a String comparison
	 *
	 * @param key the key to MAC the data with
	 * @param data the data to MAC and compare with
	 * @param mac the existing MAC, generally sent by the third party
	 * @return whether the two values are String.equal
	 */
	boolean areMACValuesEqual(Key key, byte[] data, String mac);

	/**
	 * Creates a IV for use in crypto functions
	 *
	 * @return a 16 byte (128 bit) IV
	 */
	IvParameterSpec generateIV();

	/**
	 * Converts the supplied string to an IV for crypto functions
	 *
	 * @param iv to convert
	 * @return the IV converted
	 */
	IvParameterSpec convertByteToIV(byte[] iv);
}
