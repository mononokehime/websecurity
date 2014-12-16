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

public interface SecurityRequestConstants {

	String SESSION_KEYS = "SESSION_KEYS";

	String ENCRYPTED_JSON_CONTENT_TYPE = "application/x-mep-encrypted-json;charset=UTF-8";

	String JSON_CONTENT_TYPE = "application/json;charset=UTF-8";

	String RESPONSE_ID_PARAMETER = "x-response-id";

	String REQUEST_ID_PARAMETER = "x-request-id";
	/*
	 * The header key name for the MAC value to put in/get from the header
	 */
	String X_MEP_MAC = "x-mep-mac";
	/*
	 * The header key name for the IV to put in/get from the header
	 */
	String X_MEP_ENC_IV = "x-mep-enc-iv";

	/*
	 * The header key name for the location to put in/get from the header
	 */
	String LOCATION = "location";

	/*
	 * The name of the parameter for an encrypted GET request query string
	 */
	String ENCRYPTED_STRING_PARAMETER_NAME = "eq";

	/*
	 * JVM parameter that tells the SecurityFilter whether to process the request or not. Most deployments
	 * will probably have this off as support was added in BBM Money project. Not having the parameter assumes skip the
	 * filter
	 */
	String ENHANCED_SECURITY_ENABLED = "enhancedSecurityEnabled";

	/*
	 * JVM parameter that tells the filter whether request encryption is enabled or not. Most deployments will probably
	 * have this off as support was added in BBM Money project
	 */
	String ENCRYPTION_ENABLED = "encryptionEnabled";

	String SUPPORTED_ENCODING = "UTF-8";
}