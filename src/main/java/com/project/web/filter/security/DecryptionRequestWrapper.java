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
import com.monitise.ep.commons.cryptography.EnhancedSecuritySessionKeys;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Key;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class DecryptionRequestWrapper extends HttpServletRequestWrapper implements SecurityRequestConstants {
	private final EnhancedSecurityModelCryptoUtil enhancedSecurityModelCryptoUtil;
	private String contentType;
	private final List<String> contentTypes = new ArrayList<String>();
	private final String contentTypeHeader = "Content-Type";

	public DecryptionRequestWrapper(HttpServletRequest request, HttpServletResponse response,
									EnhancedSecurityModelCryptoUtil enhancedSecurityModelCryptoUtil) throws IOException {
		super(request);
		this.enhancedSecurityModelCryptoUtil = enhancedSecurityModelCryptoUtil;

		// we need to retain the body as this will be consumed when checking the MAC
		// this needs to be before header check as need to check the content type if there is
		// a request body. If there is no request body, then content type is not set
		final byte[] requestBody = IOUtils.toByteArray(request.getInputStream());
		// before doing anything, let's check the headers are valid
		if (!hasValidHeaders(request, requestBody)) {
			LOG.error("Headers are not valid, rejecting request.");
			getSession().invalidate();
			//throw new RestException(AuthenticationErrors.BAD_REQUEST);
			throw new RuntimeException();
		}

		final EnhancedSecuritySessionKeys keys = (EnhancedSecuritySessionKeys)request
				.getSession().getAttribute(SecurityRequestConstants.SESSION_KEYS);

		if (!isValidMAC(request, keys.getSMK(), requestBody)) {
			LOG.warn("MAC is not valid, rejecting request.");
			request.getSession().invalidate();
			//throw new RestException(AuthenticationErrors.BAD_REQUEST);
			throw new RuntimeException();
		}
		// we've already checked that encryption enabled and if so, with correct header. If the IV header exists, then
		// encryption is enabled
		if (isEncrypted(request)) {
			// set the content type to JSON unencrypted
			if (requestBody.length > 0) {
				// this is the actual payload that will be processed
				// only do this if encryption header is set
				final byte[] iv = getIVFromHeader(request);
				setContentType(JSON_CONTENT_TYPE);
				this.decryptedBody = enhancedSecurityModelCryptoUtil.decryptData(keys.getSEK(), iv, requestBody);
			}
		} else {
			this.decryptedBody = requestBody;
		}
	}

	@Override
	public ServletInputStream getInputStream() throws IOException {
		final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(decryptedBody);
		ServletInputStream servletInputStream = new ServletInputStream() {
			@Override
			public int read() throws IOException {
				return byteArrayInputStream.read();
			}
		};
		return servletInputStream;
	}

	@Override
	public BufferedReader getReader() throws IOException {
		return new BufferedReader(new InputStreamReader(this.getInputStream()));
	}

	@Override
	public String getContentType() {
		if (this.contentType == null) {
			this.contentType = super.getContentType();
		}
		return this.contentType;
	}

	@Override
	public Enumeration<String> getHeaders(String name) {
		// Spring uses get headers rather than getheader and so we need to over-ride so the updated content type is
		// returned in the ESM this is application/json and not application/x-mep-encrypted-json
		if (contentTypeHeader.equals(name)) {
			return Collections.enumeration(contentTypes);
		}
		return super.getHeaders(name);
	}

	private void setContentType(String contentType) {
		if (contentType != null) {
			contentTypes.add(contentType);
			this.contentType = contentType;
		}
	}

	protected boolean hasEncryptedParameters() {
		return isEncrypted(this) && !Strings.isEmptyOrNull(super.getParameter(ENCRYPTED_STRING_PARAMETER_NAME));
	}

	protected void forwardWithDecryptedParameters(EncryptionResponseWrapper responseWrapper, String pathWithoutContext)
			throws ServletException, IOException {
		final String encryptedRequestParam = getParameter(ENCRYPTED_STRING_PARAMETER_NAME);
		if (LOG.isDebugEnabled()) {
			LOG.debug("encryptedRequestParam is:" + encryptedRequestParam);
		}
		final byte[] rawEncryptedRequestParam = Base64.decodeBase64(encryptedRequestParam);
		final byte[] iv = getIVFromHeader(this);
		final EnhancedSecuritySessionKeys keys = (EnhancedSecuritySessionKeys)
				getSession().getAttribute(SecurityRequestConstants.SESSION_KEYS);
		// now we need to unencrypt
		final String queryStr = new String(enhancedSecurityModelCryptoUtil.decryptData(keys.getSEK(), iv,
			rawEncryptedRequestParam), SUPPORTED_ENCODING);
		if (LOG.isDebugEnabled()) {
			LOG.debug("Request query string is:" + queryStr);
		}
		// set the content type to JSON unencrypted
		setContentType(JSON_CONTENT_TYPE);
		final String forwardTo = pathWithoutContext + queryStr;
		RequestDispatcher rd = getRequestDispatcher(forwardTo);
		rd.forward(this, responseWrapper);
	}

	private boolean isEncrypted(HttpServletRequest request) {
		return !Strings.isEmptyOrNull(request.getHeader(SecurityFilter.X_MEP_ENC_IV));
	}

	private boolean isValidMAC(HttpServletRequest request, Key key, byte[] requestBody) {


		return enhancedSecurityModelCryptoUtil.areMACValuesEqual(key, stringToMAC, macFromClient);
	}

	private boolean hasValidHeaders(HttpServletRequest request, byte[] requestBody) {
		return checkCorrectEncryptionHeader(request, requestBody) && checkXRequestIDIsOk(request)
				&& !Strings.isEmptyOrNull(request.getHeader(DuplicateRequestCheckInterceptor.REQUEST_ID_PARAMETER))
				&& !Strings.isEmptyOrNull(request.getHeader(X_MEP_MAC));
	}

	private boolean checkCorrectEncryptionHeader(HttpServletRequest request, byte[] requestBody) {

		// body should have length or have query string for the IV to be included
		if (!Strings.isEmptyOrNull(request.getQueryString()) || requestBody.length > 0) {
			// if enabled and header exists, return true
			if (encryptionEnabled && !Strings.isEmptyOrNull(request.getHeader(X_MEP_ENC_IV))) {
				return true;
			}
			// if disabled and header doesn't exist, return true
			if (!encryptionEnabled && Strings.isEmptyOrNull(request.getHeader(X_MEP_ENC_IV))) {
				return true;
			}
			return false;
		}
		// finally it could just be enabled but with nothing to decrypt
		// so we shouldn't have an IV header
		return Strings.isEmptyOrNull(request.getHeader(X_MEP_ENC_IV));
	}

	private boolean checkXRequestIDIsOk(HttpServletRequest request) {
		// the previous request id needs to be greater than than the current request id
		final Long previousRequestId = new Long((String)request.getSession().getAttribute(
			DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER));
		final Long currentRequestId = new Long(getHeader(DuplicateRequestCheckInterceptor.REQUEST_ID_PARAMETER));
		if (currentRequestId > previousRequestId) {
			return true;
		}
		LOG.error("currentRequestId is not greater than previousRequestId, rejecting request.");
		getSession().invalidate();
		//hrow new RestException(AuthenticationErrors.BAD_REQUEST);
		throw new RuntimeException();
	}

	private byte[] getIVFromHeader(HttpServletRequest request) {
		try {
			return Hex.decodeHex(request.getHeader(X_MEP_ENC_IV).toCharArray());
		} catch (DecoderException e) {
			LOG.warn("IV is not valid, rejecting request.");
			getSession().invalidate();
			throw new RuntimeException();
		}
	}

	private final boolean encryptionEnabled = new Boolean(System.getProperty(ENCRYPTION_ENABLED));
	private byte[] decryptedBody;
	private static final Logger LOG = LoggerFactory.getLogger(DecryptionRequestWrapper.class);
}