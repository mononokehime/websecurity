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
 */

package com.monitise.ep.commons.cryptography;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.fail;

import java.security.Key;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

/**
 * Tests for the EnhancedSecurityModelKeyExchangeImpl
 *
 * @author MacDermotF
 */
public class EnhancedSecurityModelKeyExchangeImplTest {

	@Test
	public void testCreateSMK() throws Exception {
		try {

			System.setProperty("javax.net.ssl.keyStore", fileName);
			System.setProperty("javax.net.ssl.keyStorePassword", passPhrase);
			System.setProperty(privateKeyAliasKey, aliasName);
			EnhancedSecurityModelKeyExchangeImpl enhancedSecurityModelKeyExchange = new EnhancedSecurityModelKeyExchangeImpl();
			Key testSMK = enhancedSecurityModelKeyExchange.createSMK(Hex.decodeHex(serverSMKComponent.toCharArray()),
				encryptedClientSMKComponent, aliasName);
			assertEquals("Algorithm not correct", "HmacSHA256", testSMK.getAlgorithm());
			assertEquals("length is not correct", 32, testSMK.getEncoded().length);
			assertEquals("Key not correct", smkAsString, Hex.encodeHexString(testSMK.getEncoded()));
		} finally {
			System.clearProperty("javax.net.ssl.keyStore");
			System.clearProperty("javax.net.ssl.keyStorePassword");
			System.clearProperty(privateKeyAliasKey);
		}
	}

	@Test
	public void testCreateSMKInvalidAlias() throws Exception {
		try {

			System.setProperty("javax.net.ssl.keyStore", fileName);
			System.setProperty("javax.net.ssl.keyStorePassword", passPhrase);
			System.setProperty(privateKeyAliasKey, aliasName);
			EnhancedSecurityModelKeyExchangeImpl enhancedSecurityModelKeyExchange = new EnhancedSecurityModelKeyExchangeImpl();
			try {
				enhancedSecurityModelKeyExchange.createSMK(Hex.decodeHex(serverSMKComponent.toCharArray()),
					encryptedClientSMKComponent, invalidAliasName);
			} catch (IllegalArgumentException e) {
				assertEquals("Invalid error message", "No system property for esm.alias.server_cert1 configured.",
					e.getMessage());
			}
		} finally {
			System.clearProperty("javax.net.ssl.keyStore");
			System.clearProperty("javax.net.ssl.keyStorePassword");
			System.clearProperty(privateKeyAliasKey);
		}
	}

	@Test
	public void testCreateSMKNoPrivateKey() throws Exception {
		try {

			System.setProperty("javax.net.ssl.keyStore", fileName);
			System.setProperty("javax.net.ssl.keyStorePassword", passPhrase);
			EnhancedSecurityModelKeyExchangeImpl enhancedSecurityModelKeyExchange = new EnhancedSecurityModelKeyExchangeImpl();
			try {
				enhancedSecurityModelKeyExchange.createSMK(Hex.decodeHex(serverSMKComponent.toCharArray()),
					encryptedClientSMKComponent, aliasName);
			} catch (IllegalArgumentException e) {
				assertEquals("Invalid error message", "No system property for esm.alias.server_cert configured.",
					e.getMessage());
			}
		} finally {
			System.clearProperty("javax.net.ssl.keyStore");
			System.clearProperty("javax.net.ssl.keyStorePassword");
		}
	}

	@Test
	public void testCreateSMKBlankAliasPassed() throws Exception {
		try {

			System.setProperty("javax.net.ssl.keyStore", fileName);
			System.setProperty("javax.net.ssl.keyStorePassword", passPhrase);
			System.setProperty(privateKeyAliasKey, aliasName);
			EnhancedSecurityModelKeyExchangeImpl enhancedSecurityModelKeyExchange = new EnhancedSecurityModelKeyExchangeImpl();
			try {
				enhancedSecurityModelKeyExchange.createSMK(Hex.decodeHex(serverSMKComponent.toCharArray()),
					encryptedClientSMKComponent, "");
			} catch (IllegalArgumentException e) {
				assertEquals("Invalid error message", "No system property for esm.alias. configured.", e.getMessage());
			}
		} finally {
			System.clearProperty("javax.net.ssl.keyStore");
			System.clearProperty("javax.net.ssl.keyStorePassword");
			System.clearProperty(privateKeyAliasKey);
		}
	}

	@Test
	public void testCreateSMKDecoderExeption() throws Exception {
		System.setProperty("javax.net.ssl.keyStore", fileName);
		System.setProperty("javax.net.ssl.keyStorePassword", passPhrase);
		System.setProperty(privateKeyAliasKey, aliasName);
		EnhancedSecurityModelKeyExchangeImpl enhancedSecurityModelKeyExchange = new EnhancedSecurityModelKeyExchangeImpl();
		String test = new String(Base64.encodeBase64URLSafe(clientSMKComponent.getBytes()));
		try {
			enhancedSecurityModelKeyExchange
				.createSMK(Hex.decodeHex(serverSMKComponent.toCharArray()), test, aliasName);
			fail("No IllegalArgumentException thrown");
		} catch (IllegalArgumentException e) {
			// expected
		}

		finally {
			System.clearProperty("javax.net.ssl.keyStore");
			System.clearProperty("javax.net.ssl.keyStorePassword");
			System.clearProperty(privateKeyAliasKey);
		}
	}

	@Test
	public void testCreateSEK() throws Exception {
		try {
			System.setProperty("javax.net.ssl.keyStore", fileName);
			System.setProperty("javax.net.ssl.keyStorePassword", passPhrase);
			System.setProperty(privateKeyAliasKey, aliasName);
			EnhancedSecurityModelKeyExchangeImpl enhancedSecurityModelKeyExchange = new EnhancedSecurityModelKeyExchangeImpl();
			Key testSEK = enhancedSecurityModelKeyExchange.createSEK(Hex.decodeHex(serverSEKComponent.toCharArray()),
				encryptedClientSEKComponent, aliasName);
			assertEquals("Algorithm not correct", "AES", testSEK.getAlgorithm());
			assertEquals("length is not correct", 16, testSEK.getEncoded().length);
			assertEquals("Key not correct", sekAsString, Hex.encodeHexString(testSEK.getEncoded()));
		} finally {
			System.clearProperty("javax.net.ssl.keyStore");
			System.clearProperty("javax.net.ssl.keyStorePassword");
			System.clearProperty(privateKeyAliasKey);
		}
	}

	@Test
	public void testCreateSEKDecoderExeption() throws Exception {
		System.setProperty("javax.net.ssl.keyStore", fileName);
		System.setProperty("javax.net.ssl.keyStorePassword", passPhrase);
		System.setProperty(privateKeyAliasKey, aliasName);
		EnhancedSecurityModelKeyExchangeImpl enhancedSecurityModelKeyExchange = new EnhancedSecurityModelKeyExchangeImpl();
		String test = new String(Base64.encodeBase64URLSafe(clientSMKComponent.getBytes()));
		try {
			enhancedSecurityModelKeyExchange
				.createSEK(Hex.decodeHex(serverSMKComponent.toCharArray()), test, aliasName);
			fail("No IllegalArgumentException thrown");
		} catch (IllegalArgumentException e) {
			// expected
		} finally {
			System.clearProperty("javax.net.ssl.keyStore");
			System.clearProperty("javax.net.ssl.keyStorePassword");
			System.clearProperty(privateKeyAliasKey);
		}
	}

	@Test
	public void testGenerateSMKComponent() throws Exception {
		EnhancedSecurityModelKeyExchange enhancedSecurityModelKeyExchange = new EnhancedSecurityModelKeyExchangeImpl();
		byte[] macComponent = enhancedSecurityModelKeyExchange.generateMACKeyComponent();
		assertEquals("mac component length not correct", 32, macComponent.length);
	}

	@Test
	public void testGenerateSEKComponent() throws Exception {
		EnhancedSecurityModelKeyExchange enhancedSecurityModelKeyExchange = new EnhancedSecurityModelKeyExchangeImpl();
		byte[] sekComponent = enhancedSecurityModelKeyExchange.generateEncryptionKeyComponent();
		assertEquals("mac component length not correct", 16, sekComponent.length);
	}

	@Test
	public void testCreateSessionKeys() throws Exception {
		try {
			System.setProperty("javax.net.ssl.keyStore", fileName);
			System.setProperty("javax.net.ssl.keyStorePassword", passPhrase);
			System.setProperty(privateKeyAliasKey, aliasName);
			EnhancedSecurityModelKeyExchangeImpl enhancedSecurityModelKeyExchange = new EnhancedSecurityModelKeyExchangeImpl();
			EnhancedSecuritySessionKeys keys = enhancedSecurityModelKeyExchange.createSessionKeys(
				encryptedClientSMKComponent, encryptedClientSEKComponent, aliasName);
			assertNotNull("keys are null", keys);
			assertNotNull("SEK is null", keys.getSEK());
			assertNotNull("SMK is null", keys.getSMK());
			assertNotNull("getServerSEKComponent is null", keys.getServerSEKComponent());
			assertNotNull("getServerSMKComponent is null", keys.getServerSMKComponent());
			// now lets try combining to make sure keys are equal
			Key combinedSEK = enhancedSecurityModelKeyExchange.createSEK(
				Hex.decodeHex(keys.getServerSEKComponent().toCharArray()), encryptedClientSEKComponent, aliasName);
			String combinedSEKString = new String(Hex.encodeHexString(combinedSEK.getEncoded()));
			String sekFromSessionKeys = new String(Hex.encodeHexString(keys.getSEK().getEncoded()));
			assertEquals("SEKs are not equal", sekFromSessionKeys, combinedSEKString);
			Key combinedSMK = enhancedSecurityModelKeyExchange.createSMK(
				Hex.decodeHex(keys.getServerSMKComponent().toCharArray()), encryptedClientSMKComponent, aliasName);
			String combinedSMKString = new String(Hex.encodeHexString(combinedSMK.getEncoded()));
			String smkFromSessionKeys = new String(Hex.encodeHexString(keys.getSMK().getEncoded()));
			assertEquals("SMKs are not equal", smkFromSessionKeys, combinedSMKString);
		} finally {
			System.clearProperty("javax.net.ssl.keyStore");
			System.clearProperty("javax.net.ssl.keyStorePassword");
			System.clearProperty(privateKeyAliasKey);
		}
	}

	@Test
	public void testCreateSessionKeysSMKNotEqual() throws Exception {
		try {
			System.setProperty("javax.net.ssl.keyStore", fileName);
			System.setProperty("javax.net.ssl.keyStorePassword", passPhrase);
			System.setProperty(privateKeyAliasKey, aliasName);
			EnhancedSecurityModelKeyExchangeImpl enhancedSecurityModelKeyExchange = new EnhancedSecurityModelKeyExchangeImpl();
			EnhancedSecuritySessionKeys keys = enhancedSecurityModelKeyExchange.createSessionKeys(
				encryptedClientSMKComponent, encryptedClientSEKComponent, aliasName);
			assertNotNull("keys are null", keys);
			assertNotNull("SEK is null", keys.getSEK());
			assertNotNull("SMK is null", keys.getSMK());
			assertNotNull("getServerSEKComponent is null", keys.getServerSEKComponent());
			assertNotNull("getServerSMKComponent is null", keys.getServerSMKComponent());
			// now lets try combining to make sure keys are equal
			Key combinedSEK = enhancedSecurityModelKeyExchange.createSEK(
				Hex.decodeHex(keys.getServerSEKComponent().toCharArray()), encryptedClientSEKComponent, aliasName);
			String combinedSEKString = new String(Hex.encodeHexString(combinedSEK.getEncoded()));
			String sekFromSessionKeys = new String(Hex.encodeHexString(keys.getSEK().getEncoded()));
			assertEquals("SEKs are not equal", sekFromSessionKeys, combinedSEKString);
			Key combinedSMK = enhancedSecurityModelKeyExchange.createSMK(
				Hex.decodeHex(keys.getServerSMKComponent().toCharArray()), encryptedClientSMKComponent, aliasName);
			String combinedSMKString = new String(Hex.encodeHexString(combinedSMK.getEncoded()));
			String smkFromSessionKeys = new String(Hex.encodeHexString(keys.getSMK().getEncoded()));
			assertNotSame("SMKs are equal", smkFromSessionKeys, combinedSMKString);
		} finally {
			System.clearProperty("javax.net.ssl.keyStore");
			System.clearProperty("javax.net.ssl.keyStorePassword");
			System.clearProperty(privateKeyAliasKey);
		}
	}

	@Test
	public void testCreateSessionKeysSEKNotEqual() throws Exception {
		try {
			System.setProperty("javax.net.ssl.keyStore", fileName);
			System.setProperty("javax.net.ssl.keyStorePassword", passPhrase);
			System.setProperty(privateKeyAliasKey, aliasName);
			EnhancedSecurityModelKeyExchangeImpl enhancedSecurityModelKeyExchange = new EnhancedSecurityModelKeyExchangeImpl();
			EnhancedSecuritySessionKeys keys = enhancedSecurityModelKeyExchange.createSessionKeys(
				encryptedClientSMKComponent, encryptedClientSEKComponent, aliasName);
			assertNotNull("keys are null", keys);
			assertNotNull("SEK is null", keys.getSEK());
			assertNotNull("SMK is null", keys.getSMK());
			assertNotNull("getServerSEKComponent is null", keys.getServerSEKComponent());
			assertNotNull("getServerSMKComponent is null", keys.getServerSMKComponent());
			// now lets try combining to make sure keys are equal
			Key combinedSEK = enhancedSecurityModelKeyExchange.createSEK(
				Hex.decodeHex(keys.getServerSEKComponent().toCharArray()), encryptedClientSEKComponent, aliasName);
			String combinedSEKString = new String(Hex.encodeHexString(combinedSEK.getEncoded()));
			String sekFromSessionKeys = new String(Hex.encodeHexString(keys.getSEK().getEncoded()));
			assertNotSame("SEKs are equal", sekFromSessionKeys, combinedSEKString);
			Key combinedSMK = enhancedSecurityModelKeyExchange.createSMK(
				Hex.decodeHex(keys.getServerSMKComponent().toCharArray()), encryptedClientSMKComponent, aliasName);
			String combinedSMKString = new String(Hex.encodeHexString(combinedSMK.getEncoded()));
			String smkFromSessionKeys = new String(Hex.encodeHexString(keys.getSMK().getEncoded()));
			assertEquals("SMKs are not equal", smkFromSessionKeys, combinedSMKString);
		} finally {
			System.clearProperty("javax.net.ssl.keyStore");
			System.clearProperty("javax.net.ssl.keyStorePassword");
			System.clearProperty(privateKeyAliasKey);
		}
	}

	private final String serverSMKComponent = "f3992b6fb8ba781c9424c1d1d8ed6ba9ecd86dc0bbe8cf797143e5da48fafd59";
	private final String serverSEKComponent = "624412a6621734e3db4dfd9276eb8307";
	private final String clientSMKComponent = "f3992b6fb8ba781c1004c1d1d8ed6ba9ecd86dc0bbe8cf797143e5da48fafd59";
	private final String smkAsString = "c23efc59768a2b51b579804e1c62375832ba10a75f31e40902748ea12d36c6af";
	private final String sekAsString = "9ea3bdbb7e5da6c227118a8fd4f178c8";
	private final String encryptedClientSEKComponent = "KPsHzmgFS6UxupXalAs1hr0mIOwowMD1k-imFInVQcveYkul9veuLFSI8mwVLxBLpYThIKF5YPnbWFUCiOVXRxpVtF01n-cyGKFxmZdOkZU5-r2QbmxbBE9ieZt9dz8-1X_C-fMj8VgyJrjSF_B8y6JV0gNq0NRjnamEhxUurMo";
	private final String encryptedClientSMKComponent = "kAqIRosac87lPcPCfshy2rWUSPmzirkhEHRj8XGVaL5Jl3z_thsJxfWAAipL8SK3AFk48ysqfmsVpf4zQRupLAwsPMjwNLM_osPrxg2iYphZajL2n9nT52YilS2aJfaRAI_MNVlwqMZ5lXo-rhN9WE8r5ts97aG4kWDsSsm9RBI";
	private final String fileName = "test_keystore.jks";
	private final String passPhrase = "changeit";
	private final String aliasName = "server_cert";
	private final String privateKeyAliasKey = "esm.alias." + aliasName;
	private final String invalidAliasName = "server_cert1";
}