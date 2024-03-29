/*
 * Copyright  2008-2010 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.apache.xml.security.test.keys.storage;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.NoSuchElementException;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.xml.security.keys.storage.implementations.KeyStoreResolver;

/**
 * KeyStore StorageResolver test.
 */
public class KeyStoreResolverTest extends TestCase {

	private static final String BASEDIR =
	    System.getProperty("basedir") == null ? "./": System.getProperty("basedir");
	private static final String SEP = System.getProperty("file.separator");

	public KeyStoreResolverTest() {
		super("KeyStoreResolverTest");
	}

	public KeyStoreResolverTest(String name) {
		super(name);
	}

	public static Test suite() {
		return new TestSuite(KeyStoreResolverTest.class);
	}

	public void testKeyStoreResolver() throws Exception {

		FileInputStream f = new FileInputStream(BASEDIR + SEP + "data" + SEP
				+ "org" + SEP + "apache" + SEP + "xml" + SEP + "security" + SEP
				+ "samples" + SEP + "input" + SEP + "keystore2.jks");

		KeyStore ks = KeyStore.getInstance("JCEKS");
		ks.load(f, "xmlsecurity".toCharArray());

		KeyStoreResolver ksResolver = new KeyStoreResolver(ks);
		Iterator iter = ksResolver.getIterator();
		checkIterator(iter);
		
		// check new iterator starts from the beginning
		Iterator iter2 = ksResolver.getIterator();
		checkIterator(iter2);
		
		// check the iterators are independent
		// check calling next() without calling hasNext()
		iter = ksResolver.getIterator();
		iter2 = ksResolver.getIterator();
		
		while (iter.hasNext()) {
		    X509Certificate cert = (X509Certificate) iter.next();
		    X509Certificate cert2 = (X509Certificate) iter2.next();
		    if (!cert.equals(cert2)) {
		        fail("KeyStoreResolver iterators are not independent");
		    }
		}
		assertFalse(iter2.hasNext());
	}
	
	private void checkIterator(Iterator iter) {
	    int count = 0;
	    iter.hasNext(); // hasNext() is idempotent

	    while (iter.hasNext()) {
	        X509Certificate cert = (X509Certificate) iter.next();
	        cert.getSubjectDN().getName();
	        count++;
	    }

	    // The iterator skipped over symmetric keys
	    assertEquals(3, count);

	    // Cannot go beyond last element
	    try {
	        iter.next();
	        fail("Expecting NoSuchElementException");
	    } catch (NoSuchElementException e) {
	    }
	}
	
}
