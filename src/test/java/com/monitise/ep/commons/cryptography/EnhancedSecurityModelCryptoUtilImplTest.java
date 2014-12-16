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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.Key;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.Before;
import org.junit.Test;

public class EnhancedSecurityModelCryptoUtilImplTest {

	@Test
	public void testEncryptData() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		byte[] encryptedData = cryptoUtil.encryptData(sEK, iv, dataToEncrypt.getBytes());
		String theStr = Base64.encodeBase64URLSafeString(encryptedData);
		assertEquals("Encrypted string is not equal", encryptedDataString, theStr);
	}

	@Test
	public void testEncryptDataInvalidKey() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();

		try {
			cryptoUtil.encryptData(null, iv, dataToEncrypt.getBytes());
			fail("No IllegalArgumentException thrown");
		} catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testEncryptDataInvalidIV() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();

		try {
			cryptoUtil.encryptData(sEK, inValidIV, dataToEncrypt.getBytes());
			fail("No IllegalArgumentException thrown");
		} catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testEncryptDataUnequal() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		byte[] encryptedData = cryptoUtil.encryptData(sEK, iv, dataToEncrypt.getBytes());
		String str = new String(Hex.encodeHexString(encryptedData));
		assertNotSame("Encrypted string is equal", encryptedDataStringNotEqual, str);
	}

	@Test
	public void testDecryptData() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		byte[] unencoded = Base64.decodeBase64(encryptedDataString);
		byte[] decryptedData = cryptoUtil.decryptData(sEK, ivString.getBytes("UTF-8"), unencoded);
		String decryptedString = new String(decryptedData);
		assertEquals("Decrypted string is not equal", dataToEncrypt, decryptedString);
	}

	@Test
	public void testDecryptDataWithUnderScore() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		byte[] unencoded = Base64.decodeBase64(encryptedDataString);
		byte[] decryptedData = cryptoUtil.decryptData(sEK, ivString.getBytes("UTF-8"), unencoded);
		String decryptedString = new String(decryptedData);
		assertEquals("Decrypted string is not equal", dataToEncrypt, decryptedString);
	}

	@Test
	public void testDecryptDataInvalidKey() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		byte[] unencoded = Base64.decodeBase64(encryptedDataString);
		try {
			cryptoUtil.decryptData(null, ivString.getBytes("UTF-8"), unencoded);
			fail("No IllegalArgumentException thrown");
		} catch (IllegalArgumentException e) {
			assertEquals("Incorrect error message", "SEK cannot be empty", e.getMessage());
		}
	}

	@Test
	public void testDecryptDataInvalidIV() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		byte[] unencoded = Base64.decodeBase64(encryptedDataString);
		try {
			cryptoUtil.decryptData(sEK, sekComponent1.getBytes("UTF-8"), unencoded);
			fail("No IllegalArgumentException thrown");
		} catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testDecryptDataNotEqual() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		byte[] unencoded = Base64.decodeBase64(encryptedDataString);
		byte[] decryptedData = cryptoUtil.decryptData(sEK, ivString.getBytes("UTF-8"), unencoded);
		String decryptedString = new String(decryptedData);
		assertNotSame("Decrypted string is equal", dataToEncryptNotEqual, decryptedString);
	}

	@Test
	public void testGenerateIV() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		IvParameterSpec iv = cryptoUtil.generateIV();
		// IV should be 16 bytes
		assertEquals("IV is not the right length", 16, iv.getIV().length);
	}

	@Test
	public void testConvertStringToIVRequest() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		String myIv = "dba2a1b7e2b782932dcb2f9cb20c1932";

		byte[] converted = Hex.decodeHex(myIv.toCharArray());
		IvParameterSpec iv = cryptoUtil.convertByteToIV(converted);

		// IV should be 16 bytes
		assertEquals("IV is not the right length", 16, iv.getIV().length);

	}

	@Test
	public void testCalculateHMAC() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		assertEquals("MACs are not equal", macedValue, cryptoUtil.calculateHMAC(sMK, valueToMAC.getBytes()));
	}

	@Test
	public void testCalculateHMACInvalidKey() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		try {
			cryptoUtil.calculateHMAC(null, valueToMAC.getBytes());
			fail("No IllegalArgumentException thrown");
		} catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testCalculateHMACNotSame() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		assertNotSame("MACs are equal", macedValueNotSame, cryptoUtil.calculateHMAC(sMK, valueToMAC.getBytes()));
	}

	@Test
	public void testMACValuesEqual() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		assertTrue("MACs are not equal", cryptoUtil.areMACValuesEqual(sMK, valueToMAC.getBytes(), macedValue));
	}

	@Test
	public void testMACValuesUnEqual() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		assertFalse("MACs are equal", cryptoUtil.areMACValuesEqual(sMK, valueToMACUnequal.getBytes(), macedValue));
	}

	@Before
	public void setup() throws Exception {
		byte[] macComponent = Hex.decodeHex(macComponent1.toCharArray());
		byte[] macPart2KeyBytes = Hex.decodeHex(macComponent2.toCharArray());
		byte[] out = new byte[macComponent.length];
		for (int i = 0; i < macComponent.length; i++) {
			out[i] = (byte)(macComponent[i] ^ macPart2KeyBytes[i]);
		}
		sMK = new SecretKeySpec(out, "HmacSHA256");

		byte[] sekComponent = Hex.decodeHex(sekComponent1.toCharArray());
		byte[] sekPart2KeyBytes = Hex.decodeHex(sekComponent2.toCharArray());
		out = new byte[sekComponent.length];
		for (int i = 0; i < sekComponent.length; i++) {
			out[i] = (byte)(sekComponent[i] ^ sekPart2KeyBytes[i]);
		}
		sEK = new SecretKeySpec(out, "AES");
		iv = new javax.crypto.spec.IvParameterSpec(ivString.getBytes());
		inValidIV = new javax.crypto.spec.IvParameterSpec(sekComponent1.getBytes());
	}

	private final String encryptedDataStringNotEqual = "e6c0fd0d2f7ea43b3d9e9ff807c706b18a8147fdda7f67defba2a42299f9b377a2226a83348015b7f48ba68dc034b00d959e2d62ffd315cd2c875cb50372513bdc61df2efa20adb40192cb6cde04f6f7c3f958acaad3a3e770902ac871d6c2bbef84489ff25295d56de43e069cbde6c4a0ff3d5e4bc9c9a0364f350bbb7b1416607bca1511fe6d348d80f566e6aa7a1db540762225dc9c191b677eab7f21d2bcc08801c38bd8046558ba652a7f6bd16c8de7b86c2b8a6e1f4b1dcab4843921b23a5329d0fc39e4dc33f536cf2e9715f7dd36bb7882c27d267666096a9b1b909061b26a4b5e3327ceb65f3f8c4616427acbc69f1f0e93329ae90b696c5b132b03ed7f613536d5de8e76df88dfae40b3633a3aadde517d0b96c2f9074715c327984";
	private final String encryptedDataString = "5sD9DS9-pDs9np_4B8cGsYqBR_3af2fe-6KkIpn5s3eiImqDNIAVt_SLpo3ANLANlZ4tYv_TFc0sh1y1A3JRO9xh3y76IK20AZLLbN4E9vfD-VisqtOj53CQKshx1sK774RIn_JSldVt5D4GnL3mxKD_PV5LycmgNk81C7t7FBZge8oVEf5tNI2A9WbmqnodtUB2IiXcnBkbZ36rfyHSvMCIAcOL2ARlWLplKn9r0WyN57hsK4puH0sdyrSEOSGyOlMp0Pw55Nwz9TbPLpcV9902u3iCwn0mdmYJapsbkJBhsmpLXjMnzrZfP4xGFkJ6y8afHw6TMprpC2lsWxMrA-1_YTU21d6Odt-I365As2M6Oq3eUX0LlsL5B0cVwyeY";
	private final String dataToEncrypt = "{\"fromAccountAlias\" : \"eMoney Account\",\"paymentAmount\" : {\"amount\" : 125000,\"currency\" : \"IDR\"},\"type\" : \"STANDARD\",\"method\" : \"ELECTRONIC\",\"paymentBeneficiary\" : {\"beneficiaryAlias\" : \"MUHAMMAD ALI\",\"accountNumber\" : \"710A000042\",\"type\" : \"STANDARD_PAYEE\",\"sortCode\" : \"001\"}}";
	private final String dataToEncryptNotEqual = "{\"frmAccountAlias\" : \"eMoney Account\",\"paymentAmount\" : {\"amount\" : 125000,\"currency\" : \"IDR\"},\"type\" : \"STANDARD\",\"method\" : \"ELECTRONIC\",\"paymentBeneficiary\" : {\"beneficiaryAlias\" : \"MUHAMMAD ALI\",\"accountNumber\" : \"710A000042\",\"type\" : \"STANDARD_PAYEE\",\"sortCode\" : \"001\"}}";
	private final String valueToMAC = "GET\napplication/x-mep-encrypted-json;charset=UTF-8\n136567270213312de706a7b300ac7aa5ea62ce103074ad\nhttp://localhost/mrs/3/activationCode";
	private final String valueToMACUnequal = "GET\napplication/x-mep-encrypted-json;charset=UTF-8\n136567270213312de706a7b300ac7aa5ea62ce103074ad\nhttp://localhost/mrs/3/activationode";
	private final String macedValue = "cVV7Ut7uLWZrFPblxLTCadBAeTb63OSbBhoFjNCk2uI=";
	private final String macedValueNotSame = "cVV7Ut7uLWZrFPblxLTCadBAeTb63OSbBhoFjNck2uI=";
	private final String macComponent2 = "aaef9260068b76dbf7fbf6130b782977d9032065d638910290037e660cabb776";
	private final String macComponent1 = "68407465a402d85892ffe88ced3b5eb10756800011a5a785a9e4322858933c9f";
	private final String sekComponent2 = "624412a6621734e3db4dfd9276eb8307";
	private final String sekComponent1 = "adc12498e19a321735bc8fc7ae6ee153";
	private final String ivString = "d7e6d36i81bcefa3";
	private Key sMK;
	private Key sEK;
	private IvParameterSpec iv;
	private IvParameterSpec inValidIV;
}