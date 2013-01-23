/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.sleuthkit.datamodel;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * ReprDataModel writes a String representation (containing the results of all
 * public method calls) of a Content object and its children to the given
 * Appendable.
 *
 * @author pmartel
 */
public class ReprDataModel {

	int indentLevel = 0;
	Appendable result, leaves;
	static final int READ_BUFFER_SIZE = 8192;
	static final String HASH_ALGORITHM = "MD5";

	/**
	 * 
	 * @param result what to append the generated representation to.
	 */
	ReprDataModel(Appendable result) {
		this.result = result;
		this.leaves= null;
	}
	/**
	 * Entry point to represent a Content object and it's children, sets up the 
	 * topDownDF method
	 * @param c the root Content object
	 */
	public void startTD(List<Content> lc) {
		List<Long> lp=new ArrayList<Long>();
		topDownDF(lc,lp);
	}
	/**
	 * Creates a top down representation of a database
	 * @param lc a list of content to be read
	 * @param lp that lc's list of parents in most recent first order
	 */
	private void topDownDF(List<Content> lc, List<Long> lp)
	{
		for(Content c : lc) {
			append(c.toString(),result);
			if(c instanceof File)
			{
				readContent(c);
			}
			nl(result);
			lp.add(0,c.getId());
			try {
				if (c.getChildren().isEmpty())
				{
					append(lp.toString(), leaves);
					nl(leaves);
				}
				else
				{
					topDownDF(c.getChildren(),new ArrayList<Long>(lp));
				}
			} catch (TskCoreException ex) {
				throw new RuntimeException(ex);
			}
			lp.remove(0);
		}
	}
	/**
	 * Creates a sequential representation of a database
	 * @param lc a list of content to be read
	 * @param lp that lc's list of parents in most recent first order
	 */
	public void startSeq(SleuthkitCase sk) throws TskCoreException
	{
		int x = 1;
		Content c;
		while ((c = sk.getContentById(x))!=null)
		{
			append(c.toString(),result);
			if(c instanceof File)
			{
				readContent(c);
			}
			nl(result);
			x++;
		}
	}
	
	private void nl(Appendable inp) {
		append("\n", inp);
	}

	private void readContent(Content c) {
		long size = c.getSize();
		byte[] readBuffer = new byte[READ_BUFFER_SIZE];
		try {
			MessageDigest md5 = MessageDigest.getInstance("MD5");

			for (long i = 0; i < size; i = i + READ_BUFFER_SIZE) {
				int read = c.read(readBuffer, i, Math.min(size - i, READ_BUFFER_SIZE));
				md5.update(readBuffer);
			}
			String hash = toHex(md5.digest());

			append("md5=" + hash, result);

		} catch (TskCoreException ex) {
			append(ex.toString(), result);
		} catch (NoSuchAlgorithmException ex) {
			throw new RuntimeException(ex);
		}
	}

	private String toHex(byte[] bytes) {
		StringBuilder hex = new StringBuilder();
		for (byte b : bytes) {
			hex.append(String.format("%02x", b & 0xFF));
		}
		return hex.toString();
	}

	private void append(CharSequence s, Appendable f) {
		try {
			//System.out.append(s);
			//System.out.flush();
			f.append(s);
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
	}
	/**
	 * Sets the leaves appendable
	 * @param lvs what to append leaves to
	 */
	public void setLeaves(Appendable lvs)
	{
		this.leaves=lvs;
	}
}
