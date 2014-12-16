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
import org.apache.commons.codec.binary.Hex;
import org.springframework.http.HttpStatus;

import javax.crypto.spec.IvParameterSpec;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.io.PrintWriter;

public class EncryptionResponseWrapper extends HttpServletResponseWrapper implements SecurityRequestConstants {
	private final ServletOutputStreamCopier bufferedServletOut = new ServletOutputStreamCopier();
	private PrintWriter printWriter;
	private ServletOutputStream outputStream;
	private int httpStatus = SC_OK;
	private String location;
	public EncryptionResponseWrapper(HttpServletResponse response) {
		super(response);
	}

	@Override
	public PrintWriter getWriter() throws IOException {
		if (this.printWriter == null) {
			this.printWriter = new PrintWriter(this.bufferedServletOut);
			return this.printWriter;
		}
		if (this.outputStream != null) {
			throw new IllegalStateException("The Servlet API forbids calling getWriter( ) after"
					+ " getOutputStream( ) has been called");
		}
		this.outputStream = this.bufferedServletOut;
		return new PrintWriter(this.outputStream);
	}

	@Override
	public ServletOutputStream getOutputStream() throws IOException {
		if (this.printWriter != null) {
			throw new IllegalStateException("The Servlet API forbids calling getOutputStream( ) after"
					+ " getWriter( ) has been called");
		}

		if (this.outputStream == null) {
			this.outputStream = this.bufferedServletOut;
		}
		return this.outputStream;
	}

	@Override
	public void flushBuffer() throws IOException {
		// override methods that deal with the response buffer
		if (this.outputStream != null) {
			this.outputStream.flush();
		} else if (this.printWriter != null) {
			this.printWriter.flush();
		}
	}

	/**
	 * Encrypts the response if encryption is required. Subsequently MAC sets a MAC in the response
	 * 
	 * @param request the request to encrypt (if there is a request body)
	 * @param enhancedSecurityModelCryptoUtil the crypto util for encrypt operations
	 * @throws java.io.IOException if there is a problem writing to the response
	 */
	protected void encryptResponse(HttpServletRequest request,
			EnhancedSecurityModelCryptoUtil enhancedSecurityModelCryptoUtil) throws IOException {
		final EnhancedSecuritySessionKeys keys = (EnhancedSecuritySessionKeys)request
			.getSession().getAttribute(SecurityRequestConstants.SESSION_KEYS);

		byte[] responseData = getServletOutputStreamCopier().getBuffer();
		final String ivString;
		final String contentType;
		if (isResponseBodyToEncrypt(responseData)) {
			final IvParameterSpec iv = enhancedSecurityModelCryptoUtil.generateIV();

			ivString = Hex.encodeHexString(iv.getIV());

		} else {
			ivString = null;
		}
		contentType = determineContentType(responseData);
		macResponse(request, enhancedSecurityModelCryptoUtil, keys, responseData, ivString, contentType);
	}

	/**
	 * Sets the content type and sets a MAC i n the response header
	 *
	 * @param request the request for obtaining headers
	 * @param enhancedSecurityModelCryptoUtil the crypto util for MAC operations
	 * @param keys the key to use for MAC signing
	 * @param responseData the response data
	 * @param ivString the iv string if response data is encrypted
	 * @param contentType the content type
	 * @throws java.io.IOException if there is a problem writing to the response
	 */
	protected void macResponse(HttpServletRequest request,
			EnhancedSecurityModelCryptoUtil enhancedSecurityModelCryptoUtil, EnhancedSecuritySessionKeys keys,
			byte[] responseData, String ivString, String contentType) throws IOException {

		super.setContentType(contentType);
		final String responseID = (String)request.getSession().getAttribute(
			DuplicateRequestCheckInterceptor.RESPONSE_ID_PARAMETER);
		// add the values we need to the header
		super.addHeader(X_MEP_MAC, macString);
		writeResponse(responseData);
	}

	private void writeResponse(byte[] responseData) throws IOException {
		super.setCharacterEncoding(SUPPORTED_ENCODING);
		super.setContentLength(responseData.length);
		super.getOutputStream().write(responseData);
		super.flushBuffer();
	}

	@Override
	public int getBufferSize() {
		return this.bufferedServletOut.getBuffer().length;
	}

	@Override
	public void reset() {
		this.bufferedServletOut.reset();
		this.httpStatus = SC_OK;
	}

	@Override
	public void resetBuffer() {
		this.bufferedServletOut.reset();
	}

	@Override
	public void setBufferSize(int size) {
		this.bufferedServletOut.setBufferSize(size);
	}

	@Override
	public void sendError(int sc) throws IOException {
		httpStatus = sc;
		super.sendError(sc);
	}

	@Override
	public void sendError(int sc, String msg) throws IOException {
		httpStatus = sc;
		super.sendError(sc, msg);
	}

	@Override
	public void setStatus(int sc) {
		httpStatus = sc;
		super.setStatus(sc);
	}

	@Override
	public void sendRedirect(String location) throws IOException {
		httpStatus = SC_MOVED_TEMPORARILY;
		super.sendRedirect(location);
	}

	@Override
	public void setStatus(int status, String string) {
		super.setStatus(status, string);
		this.httpStatus = status;
	}

	@Override
	public void setHeader(String name, String value) {
		if ("Location".equalsIgnoreCase(name)) {
			this.location = value;
		}
		super.setHeader(name, value);
	}

	public int getStatus() {
		return httpStatus;
	}

	protected ServletOutputStreamCopier getServletOutputStreamCopier() {
		return this.bufferedServletOut;
	}

	/**
	 * Checks that there is a response body to encrypt. Based on a response data length of greater than 0 and that
	 * encryption is enabled.
	 * 
	 * @param responseData the data to check the length against
	 * @return the result of the check
	 */
	private boolean isResponseBodyToEncrypt(byte[] responseData) {
		return encryptionEnabled && responseData != null && responseData.length > 0;
	}

	private byte[] getNonNullResponse(byte[] data) {
		if (data == null) {
			return new byte[0];
		}
		return data;
	}

	private String determineContentType(byte[] responseData) {
		// check to see if encryption is enabled and if so that there is response data to encrypt.
		// If there is then set the content type to encrypted content type.
		// Client decryption behaviour is based on the content type we set
		if (encryptionEnabled && responseData != null && responseData.length > 0) {
			// tells the client there is content that must be decrypted
			return ENCRYPTED_JSON_CONTENT_TYPE;
		}
		// when the response returns a 204 or 201, the response is stripped of a
		// content type by the server as there is no
		// content
		if (httpStatus == HttpStatus.NO_CONTENT.value()
				|| httpStatus == HttpStatus.CREATED.value()) {
			return null;
		}
		// when a response status of 200 or 201 is returned, glassfish adds a content type of text/html
		// so we need to override that even if there is no content or the MAC check fails
		return JSON_CONTENT_TYPE;
	}

	private final boolean encryptionEnabled = new Boolean(System.getProperty(ENCRYPTION_ENABLED));
}
