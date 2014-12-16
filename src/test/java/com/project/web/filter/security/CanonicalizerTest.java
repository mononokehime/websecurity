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


import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;

public class CanonicalizerTest {

	@Test
	public void normaliseURL() throws Exception {
		String url = "/MyResource";
		String expectedUrl = "/MyResource";
		String normalURL = Canonicalizer.normaliseURI(url, null);
		assertEquals("URI is not normal", expectedUrl, normalURL);
	}

	@Test
	public void normaliseURLWithRelativePath() throws Exception {
		String url = "a/b/X/../c";
		String expectedUrl = "a/b/c";
		String normalURL = Canonicalizer.normaliseURI(url, null);
		assertEquals("URI is not normal", expectedUrl, normalURL);
	}

	@Test
	public void normaliseURLWithExtraDividers() throws Exception {
		String url = "/A/B//c";
		String expectedUrl = "/A/B/c";
		String normalURL = Canonicalizer.normaliseURI(url, null);
		assertEquals("URI is not normal", expectedUrl, normalURL);
	}

	@Test
	public void normaliseURLWithQueryString() throws Exception {
		String url = "/mrs/3/activationCode";
		String queryString = "clientVersion=1.04&clientType=Permata|0.33.9|null|Research In Motion 8520|BlackBerry|5.2.0.10&msisdn=6212345432132&applicationName=Permata";
		String expectedUrl = "/mrs/3/activationCode?applicationName=Permata&clientType=Permata%7C0.33.9%7Cnull%7CResearch%20In%20Motion%208520%7CBlackBerry%7C5.2.0.10&clientVersion=1.04&msisdn=6212345432132";
		String normalURL = Canonicalizer.normaliseURI(url, queryString);
		assertEquals("URI is not normal", expectedUrl, normalURL);

	}

	@Test
	public void normaliseURLWithQueryStringWithPlus() throws Exception {
		String url = "/mrs/3/activationCode";
		String queryString = "clientVersion=1.04&clientType=Permata|0.33.9|null|Research+In+Motion 8520|BlackBerry|5.2.0.10&msisdn=6212345432132&applicationName=Permata";
		String expectedUrl = "/mrs/3/activationCode?applicationName=Permata&clientType=Permata%7C0.33.9%7Cnull%7CResearch%2BIn%2BMotion%208520%7CBlackBerry%7C5.2.0.10&clientVersion=1.04&msisdn=6212345432132";
		String normalURL = Canonicalizer.normaliseURI(url, queryString);
		assertEquals("URI is not normal", expectedUrl, normalURL);

	}

	@Test
	public void normaliseURLWithQueryStringWithPlusAndEmail() throws Exception {
		String url = "/mrs/3/account/payment/529999988888|11111222223333344444|rihan007@gmail.com";

		String queryString = "clientVersion=1.04&clientType=Permata|0.33.9|null|Research+In+Motion 8520|BlackBerry|5.2.0.10&msisdn=6212345432132&applicationName=Permata";
		String expectedUrl = "/mrs/3/account/payment/529999988888%7C11111222223333344444%7Crihan007%40gmail.com?applicationName=Permata&clientType=Permata%7C0.33.9%7Cnull%7CResearch%2BIn%2BMotion%208520%7CBlackBerry%7C5.2.0.10&clientVersion=1.04&msisdn=6212345432132";
		String normalURL = Canonicalizer.normaliseURI(url, queryString);
		assertEquals("URI is not normal", expectedUrl, normalURL);
	}

	@Test
	public void normaliseURLWithQueryStringAndEmptyParamValue() throws Exception {
		String url = "/mrs/3/activationCode";
		String queryString = "clientVersion=1.04&emptyParam=&clientType=Permata|0.33.9|null|Research In Motion 8520|BlackBerry|5.2.0.10&msisdn=6212345432132&applicationName=Permata";
		String expectedUrl = "/mrs/3/activationCode?applicationName=Permata&clientType=Permata%7C0.33.9%7Cnull%7CResearch%20In%20Motion%208520%7CBlackBerry%7C5.2.0.10&clientVersion=1.04&emptyParam=&msisdn=6212345432132";
		String normalURL = Canonicalizer.normaliseURI(url, queryString);
		assertEquals("URI is not normal", expectedUrl, normalURL);
	}

	@Test
	public void testBuildMACSignString() throws Exception {

		byte[] resource = Canonicalizer.buildRequestMACString(getMethod, SecurityFilter.JSON_CONTENT_TYPE,
			headers, uri, null, contentBody.getBytes());
		String result = new String(resource);
		String expectedResult = getMethod + "\n" + SecurityFilter.JSON_CONTENT_TYPE + "\n" + headers
				+ "\n" + uri + "\n" + contentBody;
		assertEquals("Strings do not match", expectedResult, result);
	}

	@Test
	public void testBuildMACNoContentTypeSignString() throws Exception {

		byte[] resource = Canonicalizer.buildResponseMACString(getMethod, null, headers, uri, null,
			responseSuccessNoBody, contentBody.getBytes());
		String result = new String(resource);
		String expectedResult = getMethod + "\n" + headers + "\n" + uri + "\n" + responseSuccessNoBody + "\n"
				+ contentBody;
		assertEquals("Strings do not match", expectedResult, result);
	}

	@Test
	public void testBuildMACBlankContentTypeSignString() throws Exception {

		byte[] resource = Canonicalizer
			.buildRequestMACString(getMethod, "", headers, uri, null, contentBody.getBytes());
		String result = new String(resource);
		String expectedResult = getMethod + "\n" + headers + "\n" + uri + "\n" + contentBody;
		assertEquals("Strings do not match", expectedResult, result);
	}

	@Test
	public void testBuildMACSignStringWithSpecialCharactersinURI() throws Exception {

		String myURL = "/mrs/3/account/payment/529999988888|11111222223333344444|rihan007@gmail.com";
		byte[] resource = Canonicalizer.buildRequestMACString(getMethod, "", headers, myURL, null,
			contentBody.getBytes());
		String result = new String(resource);
		String expectedUrl = "/mrs/3/account/payment/529999988888%7C11111222223333344444%7Crihan007%40gmail.com";
		String expectedResult = getMethod + "\n" + headers + "\n" + expectedUrl + "\n" + contentBody;
		assertEquals("Strings do not match", expectedResult, result);
	}

	@Test
	public void testCanonicalizeResponseHeadersForEnhancedSecurityMAC() throws Exception {
		String responseID = "1234";
		String ivString = "5678";
		String location = "/location";
		String result = Canonicalizer.canonicalizeResponseHeadersForEnhancedSecurityMAC(responseID, ivString, location);
		assertEquals("Headers do not match", responseHeaderWithLocationString, result);
	}

	@Test
	public void testCanonicalizeRequestHeadersForEnhancedSecurityMAC() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		String requestID = "1234";
		String ivString = "5678";
		request.addHeader(DuplicateRequestCheckInterceptor.REQUEST_ID_PARAMETER, requestID);
		request.addHeader(SecurityRequestConstants.X_MEP_ENC_IV, ivString);
		String result = Canonicalizer.canonicalizeRequestHeadersForEnhancedSecurityMAC(request);
		assertEquals("Headers do not match", requestHeaderString, result);
	}

	@Test
	public void testCanonicalizeRequestHeadersForEnhancedSecurityMACNoMatch() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		String requestID = "1234";
		String ivString = "5678";
		request.addHeader(DuplicateRequestCheckInterceptor.REQUEST_ID_PARAMETER, requestID);
		request.addHeader(SecurityRequestConstants.X_MEP_ENC_IV, ivString);
		String result = Canonicalizer.canonicalizeRequestHeadersForEnhancedSecurityMAC(request);
		assertNotSame("Headers do not match", requestHeaderStringNotMatch, result);
	}

	@Test
	public void testCanonicalizeResponseHeadersForEnhancedSecurityMACNoMatch() throws Exception {
		String responseID = "1234";
		String ivString = "5678";
		String result = Canonicalizer.canonicalizeResponseHeadersForEnhancedSecurityMAC(responseID, ivString, null);
		assertNotSame("Headers do not match", responseHeaderStringNotMatch, result);
	}

	@Test
	public void testBuildMACSignStringNullContent() throws Exception {

		byte[] resource = Canonicalizer.buildResponseMACString(getMethod,
			SecurityFilter.JSON_CONTENT_TYPE, headers, uri, null, responseSuccessNoBody, null);
		String result = new String(resource);
		String expectedResult = getMethod + "\n" + SecurityFilter.JSON_CONTENT_TYPE + "\n" + headers
				+ "\n" + uri + "\n" + responseSuccessNoBody;
		assertEquals("Strings do not match", expectedResult, result);
	}

	@Test
	public void testBuildMACSignStringEmptyContent() throws Exception {
		byte[] resource = Canonicalizer.buildResponseMACString(getMethod,
			SecurityFilter.JSON_CONTENT_TYPE, headers, uri, null, 0, "".getBytes());
		String result = new String(resource);
		String expectedResult = getMethod + "\n" + SecurityFilter.JSON_CONTENT_TYPE + "\n" + headers
				+ "\n" + uri;
		assertEquals("Strings do not match", expectedResult, result);
	}

	@Test
	public void testBuildMACResponseStringNoHeaders() throws Exception {

		byte[] resource = Canonicalizer.buildResponseMACString(getMethod,
			SecurityFilter.JSON_CONTENT_TYPE, null, uri, null, 200, contentBody.getBytes());
		String result = new String(resource);
		String expectedResult = getMethod + "\n" + SecurityFilter.JSON_CONTENT_TYPE + "\n" + uri + "\n"
				+ "200" + "\n" + contentBody;
		assertEquals("Strings do not match", expectedResult, result);
	}

	@Test
	public void normaliseURLWithChinese() throws Exception {
		String url = "a/b/X/../c/";
		String q = new String("j=\u8ABF\u67E5\u767C\u73FE");
		String expectedUrl = "a/b/c/?j=%E8%AA%BF%E6%9F%A5%E7%99%BC%E7%8F%BE";
		String normalURL = Canonicalizer.normaliseURI(url, q);
		assertEquals("URI is not normal", expectedUrl, normalURL);
	}

	@Test
	public void normaliseURLWithChineseParamName() throws Exception {
		String url = "a/b/X/../c/";
		String q = new String("\u7368\u7ACB\u81EA\u4E3B=\u8ABF\u67E5\u767C\u73FE");
		String expectedUrl = "a/b/c/?%E7%8D%A8%E7%AB%8B%E8%87%AA%E4%B8%BB=%E8%AA%BF%E6%9F%A5%E7%99%BC%E7%8F%BE";
		String normalURL = Canonicalizer.normaliseURI(url, q);
		assertEquals("URI is not normal", expectedUrl, normalURL);
	}

	private final int responseSuccessNoBody = 201;
	private final String getMethod = "GET";
	private final String headers = "valueonevaluetwo";
	private final String uri = "http://localhost:8080/sessionKeys";
	private final String contentBody = "e6c0fd0d2f7ea43b3d9e9";
	private final String responseHeaderWithLocationString = "location:/location\nx-mep-enc-iv:5678\nx-response-id:1234";
	private final String responseHeaderStringNotMatch = "x-mep-enc-iv:5678x-response-id:1234";
	private final String requestHeaderString = "x-mep-enc-iv:5678\nx-request-id:1234";
	private final String requestHeaderStringNotMatch = "x-mep-enc-iv:5678x-request-id:1234";
}