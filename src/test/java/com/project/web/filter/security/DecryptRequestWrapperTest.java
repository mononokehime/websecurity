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
package com.project.web.filter.security;


import com.monitise.ep.commons.cryptography.EnhancedSecurityModelCryptoUtil;
import com.monitise.ep.commons.cryptography.EnhancedSecurityModelCryptoUtilImpl;
import com.monitise.ep.commons.cryptography.EnhancedSecuritySessionKeys;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

import static org.junit.Assert.*;

public class DecryptRequestWrapperTest {

	@Test
	public void testEncryptedQueryString() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENCRYPTION_ENABLED, "true");
			session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
			request.setContentType(SecurityRequestConstants.ENCRYPTED_JSON_CONTENT_TYPE);
			request.setContent(new byte[0]);
			request.addHeader(SecurityRequestConstants.X_MEP_ENC_IV, ivString);
			request.addParameter(SecurityRequestConstants.ENCRYPTED_STRING_PARAMETER_NAME, encryptedDataString);
			request.setQueryString(queryString);
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringWithNoContent());

			// set the request values
			DecryptionRequestWrapper wrapper = new DecryptionRequestWrapper(request, response,
				enhancedSecurityModelCryptoUtil);
			assertTrue("No encrypted parameters", wrapper.hasEncryptedParameters());
			wrapper.forwardWithDecryptedParameters(new EncryptionResponseWrapper(response), path);
			// content type should be decrypted
			assertEquals("The content type is not correct", SecurityRequestConstants.JSON_CONTENT_TYPE,
				wrapper.getContentType());
		} finally {
			System.clearProperty(SecurityRequestConstants.ENCRYPTION_ENABLED);
		}
	}

	@Test
	public void testEncryptedQueryStringNoJsonHeader() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENCRYPTION_ENABLED, "true");
			session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
			request.setContent(new byte[0]);
			request.addHeader(SecurityRequestConstants.X_MEP_ENC_IV, ivString);
			request.addParameter(SecurityRequestConstants.ENCRYPTED_STRING_PARAMETER_NAME, encryptedDataString);
			request.setQueryString(queryString);
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringWithNoContent());

			// set the request values
			DecryptionRequestWrapper wrapper = new DecryptionRequestWrapper(request, response,
				enhancedSecurityModelCryptoUtil);
			assertTrue("No encrypted parameters", wrapper.hasEncryptedParameters());
			wrapper.forwardWithDecryptedParameters(new EncryptionResponseWrapper(response), path);
			// content type should be decrypted
			assertEquals("The content type is not correct", SecurityRequestConstants.JSON_CONTENT_TYPE,
				wrapper.getContentType());
		} finally {
			System.clearProperty(SecurityRequestConstants.ENCRYPTION_ENABLED);
		}
	}

	@Test
	public void testEncryptedBody() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENCRYPTION_ENABLED, "true");
			session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
			byte[] unencoded = Base64.decodeBase64(encryptedDataString);
			request.setContent(unencoded);
			request.setContentType(SecurityRequestConstants.ENCRYPTED_JSON_CONTENT_TYPE);
			request.addHeader(SecurityRequestConstants.X_MEP_ENC_IV, ivString);
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringWithContent());
			// set the request values
			DecryptionRequestWrapper wrapper = new DecryptionRequestWrapper(request, response,
				enhancedSecurityModelCryptoUtil);
			String result = IOUtils.toString(wrapper.getInputStream());
			assertEquals("The result is not correct", dataToEncrypt, result);
			// content type should be decrypted
			assertEquals("The content type is not correct", SecurityRequestConstants.JSON_CONTENT_TYPE,
				wrapper.getContentType());
			// content type should be decrypted )from getHeaders
			assertEquals("The content type is not correct", SecurityRequestConstants.JSON_CONTENT_TYPE, wrapper
				.getHeaders("Content-Type").nextElement());
		} finally {
			System.clearProperty(SecurityRequestConstants.ENCRYPTION_ENABLED);
		}
	}

	@Test
	public void testEncryptedBodyEmptyIV() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENCRYPTION_ENABLED, "true");
			session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
			byte[] unencoded = Base64.decodeBase64(encryptedDataString);
			request.setContent(unencoded);
			request.setContentType(SecurityRequestConstants.ENCRYPTED_JSON_CONTENT_TYPE);
			request.addHeader(SecurityRequestConstants.X_MEP_ENC_IV, "");
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringWithContent());
			try {
				@SuppressWarnings("unused")
				DecryptionRequestWrapper wrapper = new DecryptionRequestWrapper(request, response,
					enhancedSecurityModelCryptoUtil);
				fail("No RestException thrown");
			} catch (RuntimeException e) {
				//assertEquals("Incorrect exception thrown", "BAD_REQUEST", e.getErrorCode().getName());
			}
		} finally {
			System.clearProperty(SecurityRequestConstants.ENCRYPTION_ENABLED);
		}
	}

	@Test
	public void testEncryptedBodyInvalidRequestId() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENCRYPTION_ENABLED, "true");
			session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, requestID);
			byte[] unencoded = Base64.decodeBase64(encryptedDataString);
			request.setContent(unencoded);
			request.setContentType(SecurityRequestConstants.ENCRYPTED_JSON_CONTENT_TYPE);
			request.addHeader(SecurityRequestConstants.X_MEP_ENC_IV, ivString);
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringWithContent());
			try {
				@SuppressWarnings("unused")
				DecryptionRequestWrapper wrapper = new DecryptionRequestWrapper(request, response,
					enhancedSecurityModelCryptoUtil);
				fail("No RestException thrown");
			} catch (RuntimeException e) {
				//assertEquals("Incorrect exception thrown", "BAD_REQUEST", e.getErrorCode().getName());
			}
		} finally {
			System.clearProperty(SecurityRequestConstants.ENCRYPTION_ENABLED);
		}
	}

	@Test
	public void testEncryptedBodyNoIV() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENCRYPTION_ENABLED, "true");
			session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
			byte[] unencoded = Base64.decodeBase64(encryptedDataString);
			request.setContent(unencoded);
			request.setContentType(SecurityRequestConstants.ENCRYPTED_JSON_CONTENT_TYPE);
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringWithContent());
			// set the request values
			try {
				@SuppressWarnings("unused")
				DecryptionRequestWrapper wrapper = new DecryptionRequestWrapper(request, response,
					enhancedSecurityModelCryptoUtil);
				fail("No RestException thrown");
			} catch (RuntimeException e) {
				//assertEquals("Incorrect exception thrown", "BAD_REQUEST", e.getErrorCode().getName());
			}
		} finally {
			System.clearProperty(SecurityRequestConstants.ENCRYPTION_ENABLED);
		}
	}

	@Test
	public void testNoEncryptionWithIVHeader() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENCRYPTION_ENABLED, "false");
			session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
			request.addHeader(SecurityRequestConstants.X_MEP_ENC_IV, ivString);
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringWithContent());
			request.setContentType(SecurityRequestConstants.JSON_CONTENT_TYPE);
			byte[] unencoded = Base64.decodeBase64(encryptedDataString);
			request.setContent(unencoded);

			// set the request values
			try {
				@SuppressWarnings("unused")
				DecryptionRequestWrapper wrapper = new DecryptionRequestWrapper(request, response,
					enhancedSecurityModelCryptoUtil);
				fail("No RestException thrown");
			} catch (RuntimeException e) {
				//assertEquals("Incorrect exception thrown", "BAD_REQUEST", e.getErrorCode().getName());
			}
		} finally {
			System.clearProperty(SecurityRequestConstants.ENCRYPTION_ENABLED);
		}
	}

	@Test
	public void testNoEncryptionNoBodyWithIVHeader() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENCRYPTION_ENABLED, "false");
			session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
			request.addHeader(SecurityRequestConstants.X_MEP_ENC_IV, ivString);
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringWithNoContent());
			request.setContentType(SecurityRequestConstants.JSON_CONTENT_TYPE);
			request.setContent(new byte[0]);
			// set the request values
			try {
				@SuppressWarnings("unused")
				DecryptionRequestWrapper wrapper = new DecryptionRequestWrapper(request, response,
					enhancedSecurityModelCryptoUtil);
				fail("No RestException thrown");
			} catch (RuntimeException e) {
				//assertEquals("Incorrect exception thrown", "BAD_REQUEST", e.getErrorCode().getName());
			}
		} finally {
			System.clearProperty(SecurityRequestConstants.ENCRYPTION_ENABLED);
		}
	}

	@Test
	public void testNoEncryptionNoBodyWithQueryString() throws Exception {
		session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
		request.setMethod("GET");
		request.setQueryString(queryString);
		request.setContent(new byte[0]);
		request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringWithNoContent());
		// set the request values
		DecryptionRequestWrapper wrapper = new DecryptionRequestWrapper(request, response, enhancedSecurityModelCryptoUtil);
		// content type should be decrypted
		assertNull("The content type is not correct", wrapper.getContentType());
		assertFalse("No encrypted parameters", wrapper.hasEncryptedParameters());
	}

	@Test
	public void testEncryptDecryptData() throws Exception {
		EnhancedSecurityModelCryptoUtilImpl cryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		String ivString = "0954cfcd1194c50c3d16d94fdfd3e767";

		IvParameterSpec ivSpec = cryptoUtil.convertByteToIV(Hex.decodeHex(ivString.toCharArray()));
		String q = "msisdn=627595186911&issuerName=Permata&clientVersion=3&clientType=Permata|1.3.5|null|Research In Motion 9900|BlackBerry|4.2.0.3|en_GB|&applicationName=Permata&Session=16074998&RequestId=910608787";
		String queryString = new String(q.getBytes(), "UTF-8");
		queryString = Canonicalizer.normaliseQueryString(queryString);
		byte[] encodedQuery = cryptoUtil.encryptData(sEK, ivSpec, queryString.getBytes());

		String str = Base64.encodeBase64String(encodedQuery);

		final byte[] rawEncryptedRequestParam = Base64.decodeBase64(str);
		// now decrypt
		byte[] iv = Hex.decodeHex(ivString.toCharArray());
		final String queryStr = new String(enhancedSecurityModelCryptoUtil.decryptData(sEK, iv,
			rawEncryptedRequestParam));

		assertEquals("query strings do not match", queryString, queryStr);
	}

	@Test
	public void testDecryptClientData() throws Exception {
		String ivString = "0954cfcd1194c50c3d16d94fdfd3e767";

		String sekString = "0446d422f126919ab923fcd3340014b2";
		byte[] sekBytes = Hex.decodeHex(sekString.toCharArray());
		Key mySEK = new SecretKeySpec(sekBytes, "AES");
		String str = "lOXmxbMeCqDLEBNp4cVRKb9JQ82L2kl18T5osg7Tl0mas-WfnYIOLbIdJ9bCRWZthrnoE3DwHrJzCPsDui_jzqlCEqJMXrrrJJHkGW_a4TrvxyhJSdvo2_ntcHGzmYrH4piVpouTpE8WRY_2zNRDL9ecoJbT__YCzDA7beI_9LCRVGLRi8FTvgM46KurEHEKaWm9FK1i3fdnHcbP8OV3SBZkDDwg-E6Ehw4JpVBX2LTRn29w-L7GwWUBg9iDGe4t";
		String clientQueryString = "?msisdn=627595186924&issuerName=Permata&clientVersion=3&clientType=Permata%7c1.3.5%7cnull%7cResearch%20In%20Motion%7c9900%7cBlackBerry%7c4.2.0.38%7cen_GB%7c3&applicationName=Permata&";

		final byte[] rawEncryptedRequestParam = Base64.decodeBase64(str);
		// now decrypt
		byte[] iv = Hex.decodeHex(ivString.toCharArray());
		final String queryStr = new String(enhancedSecurityModelCryptoUtil.decryptData(mySEK, iv,
			rawEncryptedRequestParam));

		assertEquals("query strings do not match", clientQueryString, queryStr);
	}

	@Test
	public void testNoEncryptionWithBody() throws Exception {
		session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
		request.setMethod("POST");
		request.setContent(dataToEncrypt.getBytes());
		request.setContentType(SecurityRequestConstants.JSON_CONTENT_TYPE);
		request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringWithContentNoEncryption());
		// set the request values
		DecryptionRequestWrapper wrapper = new DecryptionRequestWrapper(request, response, enhancedSecurityModelCryptoUtil);
		String result = IOUtils.toString(wrapper.getInputStream());
		assertEquals("The result is not correct", dataToEncrypt, result);
		// content type should be decrypted
		assertEquals("The content type is not correct", SecurityRequestConstants.JSON_CONTENT_TYPE,
			wrapper.getContentType());
	}

	@Test
	public void testNoEncryptionWithBodyEmptyIV() throws Exception {
		session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
		request.setMethod("POST");
		request.setContent(dataToEncrypt.getBytes());
		request.addHeader(SecurityRequestConstants.X_MEP_ENC_IV, "");
		request.setContentType(SecurityRequestConstants.JSON_CONTENT_TYPE);
		request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringWithContentNoEncryption());
		// set the request values
		DecryptionRequestWrapper wrapper = new DecryptionRequestWrapper(request, response, enhancedSecurityModelCryptoUtil);
		String result = IOUtils.toString(wrapper.getInputStream());
		assertEquals("The result is not correct", dataToEncrypt, result);
		// content type should be decrypted
		assertEquals("The content type is not correct", SecurityRequestConstants.JSON_CONTENT_TYPE,
			wrapper.getContentType());
	}

	@Test
	public void testNoEncryptionWithNoBody() throws Exception {
		session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
		request.setMethod("POST");
		request.setContent(new byte[0]);
		request.setRequestURI("session");
		request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringWithNoContent());

		// set the request values
		DecryptionRequestWrapper wrapper = new DecryptionRequestWrapper(request, response, enhancedSecurityModelCryptoUtil);
		// content type should be decrypted
		assertNull("The content type is not correct", wrapper.getContentType());
		assertFalse("Encrypted parameters", wrapper.hasEncryptedParameters());
	}

	@Test
	public void testNoEncryptionWithNoBodyEmptyIV() throws Exception {
		session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
		request.setMethod("POST");
		request.setContent(new byte[0]);
		request.setRequestURI("session");
		request.addHeader(SecurityRequestConstants.X_MEP_ENC_IV, "");
		request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringWithNoContent());

		// set the request values
		DecryptionRequestWrapper wrapper = new DecryptionRequestWrapper(request, response, enhancedSecurityModelCryptoUtil);
		// content type should be decrypted
		assertNull("The content type is not correct", wrapper.getContentType());
		assertFalse("Encrypted parameters", wrapper.hasEncryptedParameters());
	}

	/**
	 * Set up test data
	 *
	 * @throws Exception
	 */
	@Before
	public void setUp() throws Exception {
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
		EnhancedSecuritySessionKeys keys = new EnhancedSecuritySessionKeys(sMK, sEK);
		request = new MockHttpServletRequest();
		session = new MockHttpSession();
		request.setSession(session);
		response = new MockHttpServletResponse();
		enhancedSecurityModelCryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();
		setHeadersinRequest(request);
		session.setAttribute(SecurityRequestConstants.SESSION_KEYS, keys);
	}

	private void setHeadersinRequest(MockHttpServletRequest request) throws Exception {
		request.addHeader(DuplicateRequestCheckInterceptor.REQUEST_ID_PARAMETER, requestID);

	}

	private String buildMACStringWithContent() throws Exception {
		byte[] unencoded = Base64.decodeBase64(encryptedDataString);
		byte[] stringToMAC = Canonicalizer.buildRequestMACString(request.getMethod(), request.getContentType(),
			Canonicalizer.canonicalizeRequestHeadersForEnhancedSecurityMAC(request), request.getRequestURI(),
			request.getQueryString(), unencoded);

		return enhancedSecurityModelCryptoUtil.calculateHMAC(sMK, stringToMAC);
	}

	private String buildMACStringWithContentNoEncryption() throws Exception {
		byte[] stringToMAC = Canonicalizer.buildRequestMACString(request.getMethod(), request.getContentType(),
			Canonicalizer.canonicalizeRequestHeadersForEnhancedSecurityMAC(request), request.getRequestURI(),
			request.getQueryString(), dataToEncrypt.getBytes());

		return enhancedSecurityModelCryptoUtil.calculateHMAC(sMK, stringToMAC);
	}

	private String buildMACStringWithNoContent() throws Exception {

		byte[] stringToMAC = Canonicalizer.buildRequestMACString(request.getMethod(), request.getContentType(),
			Canonicalizer.canonicalizeRequestHeadersForEnhancedSecurityMAC(request), request.getRequestURI(),
			request.getQueryString(), null);

		return enhancedSecurityModelCryptoUtil.calculateHMAC(sMK, stringToMAC);
	}

	private final String requestID = "999999";
	private final String previousRequestId = "999998";
	private final String encryptedDataString = "5sD9DS9-pDs9np_4B8cGsYqBR_3af2fe-6KkIpn5s3eiImqDNIAVt_SLpo3ANLANlZ4tYv_TFc0sh1y1A3JRO9xh3y76IK20AZLLbN4E9vfD-VisqtOj53CQKshx1sK774RIn_JSldVt5D4GnL3mxKD_PV5LycmgNk81C7t7FBZge8oVEf5tNI2A9WbmqnodtUB2IiXcnBkbZ36rfyHSvMCIAcOL2ARlWLplKn9r0WyN57hsK4puH0sdyrSEOSGyOlMp0Pw55Nwz9TbPLpcV9902u3iCwn0mdmYJapsbkJBhsmpLXjMnzrZfP4xGFkJ6y8afHw6TMprpC2lsWxMrA-1_YTU21d6Odt-I365As2M6Oq3eUX0LlsL5B0cVwyeY";
	private final String dataToEncrypt = "{\"fromAccountAlias\" : \"eMoney Account\",\"paymentAmount\" : {\"amount\" : 125000,\"currency\" : \"IDR\"},\"type\" : \"STANDARD\",\"method\" : \"ELECTRONIC\",\"paymentBeneficiary\" : {\"beneficiaryAlias\" : \"MUHAMMAD ALI\",\"accountNumber\" : \"710A000042\",\"type\" : \"STANDARD_PAYEE\",\"sortCode\" : \"001\"}}";
	private MockHttpServletRequest request;
	private MockHttpSession session;
	private MockHttpServletResponse response;
	private EnhancedSecurityModelCryptoUtil enhancedSecurityModelCryptoUtil;
	private final String macComponent2 = "aaef9260068b76dbf7fbf6130b782977d9032065d638910290037e660cabb776";
	private final String macComponent1 = "68407465a402d85892ffe88ced3b5eb10756800011a5a785a9e4322858933c9f";
	private final String sekComponent2 = "624412a6621734e3db4dfd9276eb8307";
	private final String sekComponent1 = "adc12498e19a321735bc8fc7ae6ee153";
	private final String ivString = "64376536643336693831626365666133";
	private final String queryString = "eq=fdgjdfigffsdgsdfgs";
	private final String path = "/mrs/3";
	private Key sMK;
	private Key sEK;
}