/*
* MONITISE CONFIDENTIAL
* ____________________
*
* Copyright 2003 - 2012 Monitise Group Limited
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Intercepts all web requests and makes sure that the request header has the
 * same token id as provided by the previous server response. This should catch
 * any duplicate submissions. The token is stored in the HttpSession and the
 * comparison is ignored if no session exists. Note that this is not a solution that
 * will work with a browser (javascript disabled) or set top box (no javascript). Furthermore it
 * relies on the ability of the client to generate a token - an assumption that should not be made.
 * It's a bit like assuming that an incoming object is valid.
 *
 * @author macdermotf
 */
public class DuplicateRequestCheckInterceptor extends HandlerInterceptorAdapter {

	private static final String MRS_ERROR_JSP = "/mrs/error.jsp";

	private static final Logger LOG = LoggerFactory.getLogger(DuplicateRequestCheckInterceptor.class);

	public static final String REQUEST_ID_PARAMETER = "X-Request-Id";
	public static final String RESPONSE_ID_PARAMETER = "X-Response-Id";

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
			Object handler) throws Exception {

		// capture system event access channel
		captureUserAgentAttribute(request);
		return doPreHandle(request, response, handler);
	}

	/*
	 * Capture User-Agent
	 */
	private void captureUserAgentAttribute(HttpServletRequest request) {
		String userAgent = request.getHeader("User-Agent");
	}

	/*
	 * A local pre handler method to simplify the preHandle() system event capture.
	 */
	private boolean doPreHandle(HttpServletRequest request, HttpServletResponse response,
			Object handler) throws Exception {

		// get the request id.
		String currentRequestId = request.getHeader(REQUEST_ID_PARAMETER);
		if (null == currentRequestId)
		{
			// then something has gone wrong as request id is required, so a bad request
			// as the parameters not complete
			LOG.error("No "+REQUEST_ID_PARAMETER+" in request so send back bad request response.");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return false;
		}
		// get the response id, which was the same as the prior request
		HttpSession session = request.getSession(false);
		if (session == null) {
			// no session, can't have a duplicate request
			return true;
		}

		// if not a new session then check parameters
		if (!session.isNew())
		{
			if (null == session.getAttribute(RESPONSE_ID_PARAMETER))
			{
				// then something has gone wrong as no session id available
				LOG.error("No "+RESPONSE_ID_PARAMETER+" in session so send back bad request response.");
				response.sendError(HttpServletResponse.SC_BAD_REQUEST);
				return false;
			}
			String lastRequestId = (String)session.getAttribute(RESPONSE_ID_PARAMETER);
			if (lastRequestId.equals(currentRequestId))
			{
				LOG.error(String.format("lastRequestId %s in the request header, is the same as currentRequestId token (duplicate request) %s",lastRequestId, currentRequestId));
				// then duplicate request
				//String errorCode = String.valueOf(AuthenticationErrors.DUPLICATE_REQUEST.getValue());
			//	String errorMessage = getMessage(AuthenticationErrors.DUPLICATE_REQUEST.getName());
				//ErrorDTO error = new ErrorDTO(errorCode, errorMessage);
				setErrorMessage(session, "");
				response.sendRedirect(MRS_ERROR_JSP);
				return false;
			}
		}

		session.setAttribute(RESPONSE_ID_PARAMETER, currentRequestId);
		response.setHeader(RESPONSE_ID_PARAMETER, currentRequestId);

		return true;

	}

	private void setErrorMessage(final HttpSession session, final String error) {
		session.setAttribute("error", error);
	}

	@Override
	public void postHandle(HttpServletRequest request, HttpServletResponse response,
			Object handler, ModelAndView modelAndView) throws Exception {

		HttpSession session = request.getSession(false);
		if (session != null) {
			String currentRequestId = request.getHeader(REQUEST_ID_PARAMETER);
			session.setAttribute(RESPONSE_ID_PARAMETER, currentRequestId);
		}
	}

	/**
	 * Once the request is processed (ie post-view rendering) clear the system event context.
	 */
	@Override
	public void afterCompletion(
			HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex)
			throws Exception {
		HttpSession session = request.getSession(false);
		if (session != null && session.getAttribute(RESPONSE_ID_PARAMETER) == null) {
			String currentRequestId = request.getHeader(REQUEST_ID_PARAMETER);
			session.setAttribute(RESPONSE_ID_PARAMETER, currentRequestId);
		}
	}

	protected final String getMessage(final String key) {
		return messages.getMessage(key, null, null);
	}
	@Autowired
	private MessageSource messages;

	public void setMessages(MessageSource messages) {
		this.messages = messages;
	}

}