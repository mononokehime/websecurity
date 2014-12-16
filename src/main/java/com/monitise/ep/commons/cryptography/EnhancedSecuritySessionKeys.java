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

import java.security.Key;

/**
 * Helper class to manage MAC and encryption session keys
 */
public final class EnhancedSecuritySessionKeys {

	/**
	 * @param sMK session MAC key
	 * @param sEK session encryption key
	 */
	public EnhancedSecuritySessionKeys(Key sMK, Key sEK) {
		this.sMK = sMK;
		this.sEK = sEK;
	}

	private final Key sMK;
	private final Key sEK;
	private String serverSMKComponent;
	private String serverSEKComponent;

	/**
	 * @param serverSMKComponent the serverSMKComponent to set
	 */
	public void setServerSMKComponent(String serverSMKComponent) {
		this.serverSMKComponent = serverSMKComponent;
	}

	/**
	 * @param serverSEKComponent the serverSEKComponent to set
	 */
	public void setServerSEKComponent(String serverSEKComponent) {
		this.serverSEKComponent = serverSEKComponent;
	}

	/**
	 * @return the sMK
	 */
	public Key getSMK() {
		return sMK;
	}

	/**
	 * @return the sEK
	 */
	public Key getSEK() {
		return sEK;
	}

	/**
	 * @return the serverSMKComponent
	 */
	public String getServerSMKComponent() {
		return serverSMKComponent;
	}

	/**
	 * @return the serverSEKComponent
	 */
	public String getServerSEKComponent() {
		return serverSEKComponent;
	}

	/**
	 * Returns a EnhancedSecuritySessionKeys with only session keys in.
	 *
	 * @return with only the Keys
	 */
	public EnhancedSecuritySessionKeys getSessionKeys() {
		return new EnhancedSecuritySessionKeys(this.sMK, this.sEK);
	}
}
