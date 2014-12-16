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


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * See http://en.wikipedia.org/wiki/URL_normalization for a reference Note: some parts of the code are adapted from:
 * http://stackoverflow.com/a/4057470/405418
 */
public class Canonicalizer {

	/**
	 * Returns a normalised URL using {@link java.net.URI}
	 *
	 * @param url the url to normalise
	 * @return a normalized URI
	 */
	public static String normaliseURI(String url, String queryString) {
		// the @ breaks the URI.create(path).normalize() call
		url = url.replace("|", "%7C").replace("@", "%40");
		return normalizePath(url) + normaliseQueryString(queryString);
	}

	/**
	 * Returns a normalised query String. Partially adapted from
	 * http://stackoverflow.com/questions/2993649/how-to-normalize-a-url-in-java/4057470#4057470 Can be called in
	 * isolation and so does not prepend a ?
	 *
	 * @param str the String to normalise
	 * @return a normalised query String
	 */
	public static String normaliseQueryString(String str) {
		// this method is used in isolation
		final SortedMap<String, String> params = createParameterMap(str);
		final String queryString;

		if (params != null && params.size() > 0) {
			String canonicalParams = canonicalizeQueryString(params);
			queryString = (canonicalParams.isEmpty() ? "" : "?" + canonicalParams);
		} else {
			queryString = "";
		}
		return queryString;
	}

	/**
	 * Creates a string of the headers in a set order to ensure this part of the MAC check is consistent. The order is
	 * X-Request-Id + value and then X-MEP-ENC-IV + value with no breaks or characters between the key/value pairs.
	 *
	 * @param request which contains the required parameters
	 * @return the concatenated string
	 */
	public static String canonicalizeRequestHeadersForEnhancedSecurityMAC(HttpServletRequest request) {
		final String requestID = request.getHeader(DuplicateRequestCheckInterceptor.REQUEST_ID_PARAMETER);
		final String ivString = request.getHeader(SecurityRequestConstants.X_MEP_ENC_IV);
		final StringBuilder sb = new StringBuilder();

		if (!Strings.isEmptyOrNull(ivString)) {
			sb.append(SecurityRequestConstants.X_MEP_ENC_IV);
			sb.append(":");
			sb.append(ivString);
			sb.append("\n");
		}
		sb.append(SecurityRequestConstants.REQUEST_ID_PARAMETER);
		sb.append(":");
		sb.append(requestID);
		return sb.toString();
	}

	/**
	 * Creates a string of the headers in a set order to ensure this part of the MAC process is consistent. The order is
	 * X-Response-Id + value and then X-MEP-ENC-IV + value with no breaks or characters between the key/value pairs.
	 *
	 * @param responseID the response id
	 * @param ivString the ivString, which can be null
	 * @param location the location, which can be null
	 * @return the concatenated string
	 */
	public static String canonicalizeResponseHeadersForEnhancedSecurityMAC(String responseID, String ivString, String location) {
		final StringBuilder sb = new StringBuilder();

		if (!Strings.isEmptyOrNull(location)) {
			sb.append(SecurityRequestConstants.LOCATION);
			sb.append(":");
			sb.append(location);
			sb.append("\n");
		}
		if (!Strings.isEmptyOrNull(ivString)) {
			sb.append(SecurityRequestConstants.X_MEP_ENC_IV);
			sb.append(":");
			sb.append(ivString);
			sb.append("\n");
		}
		sb.append(SecurityRequestConstants.RESPONSE_ID_PARAMETER);
		sb.append(":");
		sb.append(responseID);
		return sb.toString();
	}

	/**
	 * Creates a raw version of thh values to MAC
	 *
	 * @param method the request method
	 * @param contentType the content type of the request
	 * @param headers the required header String
	 * @param uri the uri
	 * @param queryString the query string
	 * @param contentBody the raw encrypted content body
	 * @return raw value of the mac String.
	 */
	public static byte[] buildRequestMACString(String method, String contentType, String headers, String uri,
			String queryString, byte[] contentBody) {
		final StringBuilder sb = new StringBuilder();
		sb.append(method);
		sb.append("\n");
		if (!Strings.isEmptyOrNull(contentType)) {
			sb.append(contentType);
			sb.append("\n");
		}
		sb.append(headers);
		sb.append("\n");
		sb.append(normaliseURI(uri, queryString));
		final byte[] returnBytes;
		if (contentBody != null && contentBody.length > 0) {
			sb.append("\n");
			final byte[] firstHalfOfMacValue = getBytesFromStringBuilder(sb);
			returnBytes = new byte[firstHalfOfMacValue.length + contentBody.length];
			System.arraycopy(firstHalfOfMacValue, 0, returnBytes, 0, firstHalfOfMacValue.length);
			System.arraycopy(contentBody, 0, returnBytes, firstHalfOfMacValue.length, contentBody.length);
		} else {
			returnBytes = getBytesFromStringBuilder(sb);
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("String to MAC****************:" + new String(returnBytes));
		}
		return returnBytes;
	}

	/**
	 * Creates a raw version of thh values to MAC
	 *
	 * @param method the request method
	 * @param contentType the content type of the request
	 * @param headers the required header String
	 * @param uri the uri
	 * @param queryString the query string
	 * @param responseCode the responseCode if there is one
	 * @param contentBody the raw encrypted content body
	 * @return raw value of the mac String.
	 */
	public static byte[] buildResponseMACString(String method, String contentType, String headers, String uri,
			String queryString, int responseCode, byte[] contentBody) {
		final StringBuilder sb = new StringBuilder();
		sb.append(method);
		if (!Strings.isEmptyOrNull(contentType)) {
			sb.append("\n");
			sb.append(contentType);
		}
		if (!Strings.isEmptyOrNull(headers)) {
			sb.append("\n");
			sb.append(headers);
		}
		sb.append("\n");
		sb.append(normaliseURI(uri, queryString));
		if (responseCode > 0) {
			sb.append("\n");
			sb.append(responseCode);
		}
		final byte[] returnBytes;
		if (contentBody != null && contentBody.length > 0) {
			sb.append("\n");
			final byte[] firstHalfOfMacValue = getBytesFromStringBuilder(sb);
			returnBytes = new byte[firstHalfOfMacValue.length + contentBody.length];
			System.arraycopy(firstHalfOfMacValue, 0, returnBytes, 0, firstHalfOfMacValue.length);
			System.arraycopy(contentBody, 0, returnBytes, firstHalfOfMacValue.length, contentBody.length);
		} else {
			returnBytes = getBytesFromStringBuilder(sb);
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("String to MAC****************:" + new String(returnBytes));
		}
		return returnBytes;
	}

	/**
	 * Takes a query string, separates the constituent name-value pairs, and stores them in a SortedMap ordered by
	 * lexicographical order. Partially adapted from
	 * http://stackoverflow.com/questions/2993649/how-to-normalize-a-url-in-java/4057470#4057470
	 *
	 * @return Null if there is no query string.
	 */
	private static SortedMap<String, String> createParameterMap(final String queryString) {
		if (queryString == null || queryString.isEmpty()) {
			return null;
		}

		final String[] pairs = queryString.split("&");
		final Map<String, String> params = new HashMap<String, String>(pairs.length);

		for (final String pair : pairs) {
			if (pair.length() == 0) {
				continue;
			}

			String[] tokens = pair.split("=", 2);
			switch (tokens.length) {
			case 1:
				if (pair.charAt(0) == '=') {
					params.put("", tokens[0]);
				} else {
					params.put(tokens[0], "");
				}
				break;
			case 2:
				params.put(tokens[0], tokens[1]);
				break;
			}
		}
		return new TreeMap<String, String>(params);
	}

	/**
	 * Canonicalize the query string. Partially adapted from
	 * http://stackoverflow.com/questions/2993649/how-to-normalize-a-url-in-java/4057470#4057470
	 *
	 * @param sortedParamMap Parameter name-value pairs in lexicographical order.
	 * @return Canonical form of query string.
	 */
	private static String canonicalizeQueryString(final SortedMap<String, String> sortedParamMap) {
		if (sortedParamMap == null || sortedParamMap.isEmpty()) {
			return "";
		}

		final StringBuffer sb = new StringBuffer(100);
		for (Map.Entry<String, String> pair : sortedParamMap.entrySet()) {
			final String key = pair.getKey().toLowerCase();
			if (key.equals("jsessionid")) {
				continue;
			}
			if (sb.length() > 0) {
				sb.append('&');
			}
			sb.append(percentEncodeRfc3986(pair.getKey()));
			sb.append('=');
			sb.append(percentEncodeRfc3986(pair.getValue()));
		}
		return sb.toString();
	}

	/**
	 * Percent-encode values according the RFC 3986. The built-in Java URLEncoder does not encode according to the RFC,
	 * so we make the extra replacements. Partially adapted from
	 * http://stackoverflow.com/questions/2993649/how-to-normalize-a-url-in-java/4057470#4057470
	 *
	 * @param string Decoded string.
	 * @return Encoded string per RFC 3986.
	 */
	private static String percentEncodeRfc3986(String string) {
		try {
			string = string.replace("+", "%2B");
			string = URLDecoder.decode(string, "UTF-8");
			string = URLEncoder.encode(string, "UTF-8");
			return string.replace("+", "%20").replace("*", "%2A").replace("%7E", "~");
		} catch (UnsupportedEncodingException e) {
			return string;
		}
	}

	private static String normalizePath(final String path) {
		URI uri = URI.create(path).normalize();
		return uri.toString().replace("%7E", "~").replace(" ", "%20");
	}

	private static byte[] getBytesFromStringBuilder(StringBuilder sb) {
		try {
			return sb.toString().getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalArgumentException(e);
		}
	}

	private static final Logger LOG = LoggerFactory.getLogger(Canonicalizer.class);
}