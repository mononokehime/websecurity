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
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Class that provides utility methods for key exchange.
 *
 * @author MacDermotF
 */
public interface EnhancedSecurityModelKeyExchange {
	/**
	 * Constant for hmacSHA256 type key generation
	 */
	String HMAC_SHA256_ALGORITHM = "HmacSHA256";

	/**
	 * Constant for AES type key generation
	 */
	String AES = "AES";

	/**
	 * Creates the session encryption key and the MAC key from the RSA encrypted components
	 *
	 * @param sMKComponent the SMK from the client (RSA encrypted and Base64 encoded)
	 * @param sEKComponent the SEK from the client (RSA encrypted and Base64 encoded)
	 * @param aliasName the alias name for the server private key
	 * @return containing the server SMK and SEK components and the SMK and SEK
	 * @throws NoSuchAlgorithmException when unable to create the keys
	 * @throws InvalidKeySpecException when unable to create the keys
	 */
	EnhancedSecuritySessionKeys createSessionKeys(String sMKComponent, String sEKComponent, String aliasName)
			throws NoSuchAlgorithmException, InvalidKeySpecException;

	/**
	 * Creates a MAC key component
	 *
	 * @return a 256 bit key component for MAC
	 * @throws NoSuchAlgorithmException when unable to create the component
	 */
	byte[] generateMACKeyComponent() throws NoSuchAlgorithmException;

	/**
	 * Creates a session key component
	 *
	 * @return a 128 bit key component for encryption
	 * @throws NoSuchAlgorithmException when unable to create the component
	 */
	byte[] generateEncryptionKeyComponent() throws NoSuchAlgorithmException;

	/**
	 * Creates the SEK based on the two provided components
	 *
	 * @param serverSEKComponent the part 1 or server component
	 * @param clientSEKComponent the part 2 or client component (RSA encrypted and Base64 encoded)
	 * @param aliasName the alias name for the server private key
	 * @return the key based on an xor calculation of the two provided components
	 * @throws NoSuchAlgorithmException when unable to create the keys
	 * @throws InvalidKeySpecException when unable to create the keys
	 */
	Key createSEK(byte[] serverSEKComponent, String clientSEKComponent, String aliasName)
			throws NoSuchAlgorithmException, InvalidKeySpecException;

	/**
	 * Creates the SMK based on the two provided components
	 *
	 * @param serverSMKComponent the part 1 or server component
	 * @param clientSMKComponent the part 2 or client component (RSA encrypted and Base64 encoded)
	 * @param aliasName the alias name for the server private key
	 * @return the key based on an xor calculation of the two provided components
	 * @throws NoSuchAlgorithmException when unable to create the keys
	 * @throws InvalidKeySpecException when unable to create the keys
	 */
	Key createSMK(byte[] serverSMKComponent, String clientSMKComponent, String aliasName)
			throws NoSuchAlgorithmException, InvalidKeySpecException;
}
