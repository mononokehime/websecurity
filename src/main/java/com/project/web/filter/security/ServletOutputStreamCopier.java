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

import javax.servlet.ServletOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ServletOutputStreamCopier extends ServletOutputStream {

	private ByteArrayOutputStream bos = new ByteArrayOutputStream();

	public byte[] getBuffer() {
		return this.bos.toByteArray();
	}

	@Override
	public void write(int data) throws IOException {
		this.bos.write(data);
	}

	public void reset() {
		this.bos.reset();
	}

	public void setBufferSize(int size) {
		this.bos = new ByteArrayOutputStream();
	}
}