/*
 * MONITISE CONFIDENTIAL
 * __________________
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
import org.apache.commons.codec.binary.Hex;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.*;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class EnhancedSecurityModelFilterTest {

	@Test
	public void testEnhancedSecurityNotEnabled() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED, "false");
			request.setContent(dataToEncrypt.getBytes());
			request.addHeader(SecurityRequestConstants.X_MEP_ENC_IV, buildMACStringNoEncryption());
			SecurityFilter filter = new SecurityFilter();
			filter.init(mockFilterConfig);
			filter.setEnhancedSecurityModelCryptoUtil(enhancedSecurityModelCryptoUtil);
			filter.setFilterByPassURLs(filterByPassURLs);
			request.setContentType(SecurityRequestConstants.JSON_CONTENT_TYPE);
			filter.doFilter(request, response, mockFilterChain);
			assertEquals("Content type is not correct", SecurityRequestConstants.JSON_CONTENT_TYPE,
				request.getContentType());
			assertNull("IV header is populated", response.getHeader(SecurityRequestConstants.X_MEP_ENC_IV));
			assertNull("MAC header is populated", response.getHeader(SecurityRequestConstants.X_MEP_MAC));
		} finally {
			System.clearProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED);
		}
	}

	@Test
	public void testEnhancedSecurityEnabledNoByPassFilterSet() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED, "true");
			request.setContent(dataToEncrypt.getBytes());
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringNoEncryption());
			SecurityFilter filter = new SecurityFilter();
			filter.init(mockFilterConfig);
			filter.setEnhancedSecurityModelCryptoUtil(enhancedSecurityModelCryptoUtil);
			filter.setFilterByPassURLs(null);
			request.setContentType(SecurityRequestConstants.JSON_CONTENT_TYPE);
			filter.doFilter(request, response, mockFilterChain);
			assertEquals("Content type is not correct", SecurityRequestConstants.JSON_CONTENT_TYPE,
				request.getContentType());
			assertNull("IV header is populated", response.getHeader(SecurityRequestConstants.X_MEP_ENC_IV));
			assertNull("MAC header is populated", response.getHeader(SecurityRequestConstants.X_MEP_MAC));
		} finally {
			System.clearProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED);
		}
	}

	@Test
	public void testSessionKeysCall() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED, "true");
			request.setContent(dataToEncrypt.getBytes());

			SecurityFilter filter = new SecurityFilter();
			filter.init(mockFilterConfig);
			filter.setEnhancedSecurityModelCryptoUtil(enhancedSecurityModelCryptoUtil);
			filter.setFilterByPassURLs(filterByPassURLs);
			filter.setCreateSessionKeysURL(createSessionKeysURI);
			request.setContentType(SecurityRequestConstants.JSON_CONTENT_TYPE);
			request.setRequestURI(createSessionKeysURI);
			filter.doFilter(request, response, mockFilterChain);
			assertEquals("Content type is not correct", SecurityRequestConstants.JSON_CONTENT_TYPE,
				request.getContentType());
			assertNotNull("MAC header is not populated", response.getHeader(SecurityRequestConstants.X_MEP_MAC));
		} finally {
			System.clearProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED);
		}
	}

	@Test
	public void testEnhancedSecurityEnabledByPassURLSet() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED, "true");
			request.setContent(dataToEncrypt.getBytes());
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringNoEncryption());
			SecurityFilter filter = new SecurityFilter();
			filter.init(mockFilterConfig);
			filter.setEnhancedSecurityModelCryptoUtil(enhancedSecurityModelCryptoUtil);
			filter.setFilterByPassURLs(filterByPassURLs);
			request.setContentType(SecurityRequestConstants.JSON_CONTENT_TYPE);
			request.setRequestURI(bypassURIRSA);
			filter.doFilter(request, response, mockFilterChain);
			assertEquals("Content type is not correct", SecurityRequestConstants.JSON_CONTENT_TYPE,
				request.getContentType());
			assertNull("IV header is populated", response.getHeader(SecurityRequestConstants.X_MEP_ENC_IV));
			assertNull("MAC header is populated", response.getHeader(SecurityRequestConstants.X_MEP_MAC));
		} finally {
			System.clearProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED);
		}
	}

	@Test
	public void testEnhancedSecurityEnabledCustomerDelete() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED, "true");
			request.setContent(dataToEncrypt.getBytes());
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringNoEncryption());
			SecurityFilter filter = new SecurityFilter();
			filter.init(mockFilterConfig);
			filter.setEnhancedSecurityModelCryptoUtil(enhancedSecurityModelCryptoUtil);
			filter.setFilterByPassURLs(filterByPassURLs);
			request.setContentType(SecurityRequestConstants.JSON_CONTENT_TYPE);
			request.setRequestURI(bypassURICustomerDelete);
			filter.doFilter(request, response, mockFilterChain);
			assertEquals("Content type is not correct", SecurityRequestConstants.JSON_CONTENT_TYPE,
				request.getContentType());
			assertNull("IV header is populated", response.getHeader(SecurityRequestConstants.X_MEP_ENC_IV));
			assertNull("MAC header is populated", response.getHeader(SecurityRequestConstants.X_MEP_MAC));
		} finally {
			System.clearProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED);
		}
	}

	@Test
	public void testEnhancedSecurityEnabledSessionDelete() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED, "true");
			request.setContent(dataToEncrypt.getBytes());
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringNoEncryption());
			SecurityFilter filter = new SecurityFilter();
			filter.init(mockFilterConfig);
			filter.setEnhancedSecurityModelCryptoUtil(enhancedSecurityModelCryptoUtil);
			filter.setFilterByPassURLs(filterByPassURLs);
			request.setContentType(SecurityRequestConstants.JSON_CONTENT_TYPE);
			request.setRequestURI(bypassURISessionDelete);
			filter.doFilter(request, response, mockFilterChain);
			assertEquals("Content type is not correct", SecurityRequestConstants.JSON_CONTENT_TYPE,
				request.getContentType());
			assertNull("IV header is populated", response.getHeader(SecurityRequestConstants.X_MEP_ENC_IV));
			assertNull("MAC header is populated", response.getHeader(SecurityRequestConstants.X_MEP_MAC));
		} finally {
			System.clearProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED);
		}
	}

	@Test
	public void testNoEncryption() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED, "true");
			request.setMethod("GET");
			request.setContent(dataToEncrypt.getBytes());
			request.setRequestURI("security/authenticate");
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACStringNoEncryption());
			session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
			SecurityFilter filter = new SecurityFilter();
			filter.init(mockFilterConfig);
			filter.setEnhancedSecurityModelCryptoUtil(enhancedSecurityModelCryptoUtil);
			filter.setFilterByPassURLs(filterByPassURLs);

			filter.doFilter(request, response, mockFilterChain);
			assertEquals("Content type is not correct", SecurityRequestConstants.JSON_CONTENT_TYPE,
				request.getContentType());
			assertNull("IV header is populated", response.getHeader(SecurityRequestConstants.X_MEP_ENC_IV));
			assertNotNull("MAC header is populated", response.getHeader(SecurityRequestConstants.X_MEP_MAC));
		} finally {
			System.clearProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED);
		}
	}

	@Test
	public void testEncryption() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED, "true");
			System.setProperty(SecurityRequestConstants.ENCRYPTION_ENABLED, "true");
			request.setContent(Hex.decodeHex(encryptedDataString.toCharArray()));
			request.setMethod("GET");
			request.setRequestURI("security/authenticate");
			request.addHeader(SecurityRequestConstants.X_MEP_ENC_IV, ivString);
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACString());

			session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
			SecurityFilter filter = new SecurityFilter();
			filter.init(mockFilterConfig);
			filter.setEnhancedSecurityModelCryptoUtil(enhancedSecurityModelCryptoUtil);
			filter.setFilterByPassURLs(filterByPassURLs);

			filter.doFilter(request, response, mockFilterChain);
			assertEquals("Content type is not correct", SecurityRequestConstants.JSON_CONTENT_TYPE,
				request.getContentType());
			assertNotNull("MAC header is not populated", response.getHeader(SecurityRequestConstants.X_MEP_MAC));
		} finally {
			System.clearProperty(SecurityRequestConstants.ENCRYPTION_ENABLED);
			System.clearProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED);
		}

	}

	@Test
	public void testEncryptionInvalidHeaders() throws Exception {
		try {
			System.setProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED, "true");
			request.setContent(Hex.decodeHex(encryptedDataString.toCharArray()));
			request.setMethod("GET");
			request.setRequestURI("security/authenticate");
			request.addHeader(SecurityRequestConstants.X_MEP_ENC_IV, ivString);
			request.addHeader(SecurityRequestConstants.X_MEP_MAC, buildMACString());
			session.setAttribute(DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER, previousRequestId);
			SecurityFilter filter = new SecurityFilter();
			filter.init(mockFilterConfig);
			filter.setEnhancedSecurityModelCryptoUtil(enhancedSecurityModelCryptoUtil);
			filter.setFilterByPassURLs(filterByPassURLs);
			try {
				filter.doFilter(request, response, mockFilterChain);
				fail("No RestException thrown");
			} catch (RuntimeException e) {
				//assertEquals("Incorrect exception thrown", "BAD_REQUEST", e.getErrorCode().getName());
			}
		} finally {
			System.clearProperty(SecurityRequestConstants.ENHANCED_SECURITY_ENABLED);
		}
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
		mockFilterConfig = new MockFilterConfig();
		mockFilterConfig.addInitParameter("filterByPassURLs", "/3/security/sessionKey");
		mockFilterChain = new MockFilterChain();
		request = new MockHttpServletRequest();
		session = new MockHttpSession();
		request.setSession(session);
		request.setContentType(SecurityRequestConstants.JSON_CONTENT_TYPE);
		response = new MockHttpServletResponse();
		enhancedSecurityModelCryptoUtil = new EnhancedSecurityModelCryptoUtilImpl();

		setHeadersinRequest(request);

		session.setAttribute(SecurityRequestConstants.SESSION_KEYS, keys);
		filterByPassURLs = new ArrayList<String>();
		filterByPassURLs.add(bypassURIRSA);
		filterByPassURLs.add(bypassURISessionDelete);
		filterByPassURLs.add(bypassURICustomerDelete);
	}

	private void setHeadersinRequest(MockHttpServletRequest request) throws Exception {
		request.addHeader(DuplicateRequestCheckInterceptor.REQUEST_ID_PARAMETER, requestID);

	}

	private String buildMACString() throws Exception {
		byte[] stringToMAC = Canonicalizer.buildRequestMACString(request.getMethod(),
			SecurityRequestConstants.JSON_CONTENT_TYPE,
			Canonicalizer.canonicalizeRequestHeadersForEnhancedSecurityMAC(request), request.getRequestURI(),
			request.getQueryString(), Hex.decodeHex(encryptedDataString.toCharArray()));

		return enhancedSecurityModelCryptoUtil.calculateHMAC(sMK, stringToMAC);
	}

	private String buildMACStringNoEncryption() throws Exception {
		byte[] stringToMAC = Canonicalizer.buildRequestMACString(request.getMethod(),
			SecurityRequestConstants.JSON_CONTENT_TYPE,
			Canonicalizer.canonicalizeRequestHeadersForEnhancedSecurityMAC(request), request.getRequestURI(),
			request.getQueryString(), dataToEncrypt.getBytes());

		return enhancedSecurityModelCryptoUtil.calculateHMAC(sMK, stringToMAC);
	}

	private final String requestID = "999999";
	private final String previousRequestId = "999998";
	private final String encryptedDataString = "e6c0fd0d2f7ea43b3d9e9ff807c706b18a8147fdda7f67defba2a42299f9b377a2226a83348015b7f48ba68dc034b00d959e2d62ffd315cd2c875cb50372513bdc61df2efa20adb40192cb6cde04f6f7c3f958acaad3a3e770902ac871d6c2bbef84489ff25295d56de43e069cbde6c4a0ff3d5e4bc9c9a0364f350bbb7b1416607bca1511fe6d348d80f566e6aa7a1db540762225dc9c191b677eab7f21d2bcc08801c38bd8046558ba652a7f6bd16c8de7b86c2b8a6e1f4b1dcab4843921b23a5329d0fc39e4dc33f536cf2e9715f7dd36bb7882c27d267666096a9b1b909061b26a4b5e3327ceb65f3f8c4616427acbc69f1f0e93329ae90b696c5b132b03ed7f613536d5de8e76df88dfae40b3633a3aadde517d0b96c2f9074715c32798";
	private final String dataToEncrypt = "{\"fromAccountAlias\" : \"eMoney Account\",\"paymentAmount\" : {\"amount\" : 125000,\"currency\" : \"IDR\"},\"type\" : \"STANDARD\",\"method\" : \"ELECTRONIC\",\"paymentBeneficiary\" : {\"beneficiaryAlias\" : \"MUHAMMAD ALI\",\"accountNumber\" : \"710A000042\",\"type\" : \"STANDARD_PAYEE\",\"sortCode\" : \"001\"}}";

	private MockFilterChain mockFilterChain;
	private MockFilterConfig mockFilterConfig;
	private MockHttpServletRequest request;
	private MockHttpSession session;
	private MockHttpServletResponse response;
	private EnhancedSecurityModelCryptoUtil enhancedSecurityModelCryptoUtil;
	private List<String> filterByPassURLs;
	private final String macComponent2 = "aaef9260068b76dbf7fbf6130b782977d9032065d638910290037e660cabb776";
	private final String macComponent1 = "68407465a402d85892ffe88ced3b5eb10756800011a5a785a9e4322858933c9f";
	private final String sekComponent2 = "624412a6621734e3db4dfd9276eb8307";
	private final String sekComponent1 = "adc12498e19a321735bc8fc7ae6ee153";
	private final String ivString = "8b61b0edf7f05b570d53803ed7ce65b9";
	private final String bypassURIRSA = "/3/security/RSAPublicKeyGET";
	private final String bypassURISessionDelete = "/3/security/sessionDELETE";
	private final String bypassURICustomerDelete = "/3/customerDELETE";
	private final String createSessionKeysURI = "/3/security/sessionKey";
	private Key sMK;
	private Key sEK;
}