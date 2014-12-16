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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Resource;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * This filter implements the Monitise enhanced security model. It performs a number of checks and operations <li>checks
 * to if enhanced security is enabled and if the request URL can bypass security checks. Enhanced security is enabled
 * via a jvm option (enhancedSecurityEnabled) and the bypass urls via spring xml</li>
 *
 * @author MacDermotF
 */
public class SecurityFilter implements Filter, SecurityRequestConstants {

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest httpServletRequest = (HttpServletRequest)servletRequest;
		HttpServletResponse httpServletResponse = (HttpServletResponse)servletResponse;
		// get the path info after the context
		final String pathWithoutContext = httpServletRequest.getRequestURI().substring(
			httpServletRequest.getContextPath().length());
		// need to add method on as some urls can be bypassed by method (e.g. session DELETE)
		if (shouldByPassSecurityEnhancements(pathWithoutContext + httpServletRequest.getMethod().toUpperCase())) {
			// bypass the filter
			if (LOG.isDebugEnabled()) {
				LOG.debug("Bypassing filter as URI is:" + pathWithoutContext);
			}
			chain.doFilter(httpServletRequest, httpServletResponse);
		} else {
			EncryptionResponseWrapper responseWrapper = new EncryptionResponseWrapper(httpServletResponse);
			if (pathWithoutContext.equals(createSessionKeysURL)) {
				handleCreateSessionKeysRequest(chain, httpServletRequest, responseWrapper);
			} else {
				DecryptionRequestWrapper decodedRequestWrapper = new DecryptionRequestWrapper(httpServletRequest,
					httpServletResponse, enhancedSecurityModelCryptoUtil);
				// wrapper the response so we can write to it

				// if a request has query params we need to decrypt any query params and then do requestDispatcher
				// to forward on to the correct resource
				if (decodedRequestWrapper.hasEncryptedParameters()) {

					decodedRequestWrapper.forwardWithDecryptedParameters(responseWrapper, pathWithoutContext);

				} else {
					chain.doFilter(decodedRequestWrapper, responseWrapper);
				}
				responseWrapper.encryptResponse(decodedRequestWrapper, enhancedSecurityModelCryptoUtil);
			}
		}
	}

	/**
	 * If the request is to create the session keys because we don't have any keys yet, we need to skip the request
	 * wrapper. However, for the response, the keys have been created and so we need to MAC sign the response
	 *
	 * @param chain the filter chain to forward on to
	 * @param httpServletRequest the servlet request
	 * @param responseWrapper the response wrapper
	 * @throws java.io.IOException when unable to write to the response
	 * @throws ServletException
	 */
	private void handleCreateSessionKeysRequest(FilterChain chain, HttpServletRequest httpServletRequest,
			EncryptionResponseWrapper responseWrapper) throws IOException, ServletException {
		// if this is the create session keys call, then we don't need to enter decryption wrapper
		chain.doFilter(httpServletRequest, responseWrapper);
		final EnhancedSecuritySessionKeys keys = (EnhancedSecuritySessionKeys)httpServletRequest
				.getSession().getAttribute(SecurityRequestConstants.SESSION_KEYS);
		responseWrapper.macResponse(httpServletRequest, enhancedSecurityModelCryptoUtil, keys, responseWrapper
				.getServletOutputStreamCopier().getBuffer(), null, JSON_CONTENT_TYPE);
	}

	@Override
	public void destroy() {

	}

	private boolean shouldByPassSecurityEnhancements(String pathWithoutContext) {
		return !enhancedSecurityEnabled || filterByPassURLs == null || filterByPassURLs.contains(pathWithoutContext);
	}

	/**
	 * @param enhancedSecurityModelCryptoUtil the enhancedSecurityModelCryptoUtil to set
	 */
	public void setEnhancedSecurityModelCryptoUtil(EnhancedSecurityModelCryptoUtil enhancedSecurityModelCryptoUtil) {
		this.enhancedSecurityModelCryptoUtil = enhancedSecurityModelCryptoUtil;
	}

	/**
	 * @param filterByPassURLs the filterByPassURLs to set
	 */
	public void setFilterByPassURLs(List<String> filterByPassURLs) {
		this.filterByPassURLs = filterByPassURLs;
	}

	/**
	 * @param createSessionKeysURL the createSessionKeysURL to set
	 */
	public void setCreateSessionKeysURL(String createSessionKeysURL) {
		this.createSessionKeysURL = createSessionKeysURL;
	}

	private static final Logger LOG = LoggerFactory.getLogger(SecurityFilter.class);

	private final boolean enhancedSecurityEnabled = new Boolean(System.getProperty(ENHANCED_SECURITY_ENABLED));

	/*
	 * The list of URLs to skip the filter actions
	 */
	private List<String> filterByPassURLs;

	/*
	 * The URL for createSessionKeysURL call. This url should bypass the DecryptionRequestWrapper
	 */
	private String createSessionKeysURL;

	@Resource
	private EnhancedSecurityModelCryptoUtil enhancedSecurityModelCryptoUtil;
}