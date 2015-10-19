/*
 * Copyright 2006 The Apache Software Foundation.
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
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
package javax.xml.crypto.test.dsig;

import javax.xml.crypto.dsig.*;
import java.security.*;

import junit.framework.*;

/**
 * Unit test for javax.xml.crypto.dsig.SignatureMethod
 *
 * @version $Id$
 * @author Valerie Peng
 */
public class SignatureMethodTest extends TestCase {

    XMLSignatureFactory factory;

    private static final String SIG_ALGOS[] = {
	SignatureMethod.DSA_SHA1,
	SignatureMethod.RSA_SHA1,
	SignatureMethod.HMAC_SHA1
    };

    public SignatureMethodTest() {
	super("SignatureMethodTest");
    }

    public SignatureMethodTest(String name) {
	super(name);
    }

    public void setUp() throws Exception { 
	factory = XMLSignatureFactory.getInstance
            ("DOM", new org.jcp.xml.dsig.internal.dom.XMLDSigRI());
    }

    public void tearDown() { }

    public void testisFeatureSupported() throws Exception {
	SignatureMethod sm;
	for (int i = 0; i < SIG_ALGOS.length; i++) {
	    String algo = SIG_ALGOS[i];
	    sm = factory.newSignatureMethod(algo, null);
	    try {
		sm.isFeatureSupported(null); 
		fail("Should raise a NPE for null feature"); 
	    } catch (NullPointerException npe) {}
	    
	    assertTrue(!sm.isFeatureSupported("not supported"));
	}
    }

    public void testConstructor() throws Exception {
	// test XMLSignatureFactory.newAlgorithmMethod
	// (String algorithm, AlgorithmParameterSpec params)
	// for generating SignatureMethod objects
	SignatureMethod sm;
	for (int i = 0; i < SIG_ALGOS.length; i++) {
	    String algo = SIG_ALGOS[i];
	    sm = factory.newSignatureMethod(algo, null);
	    assertEquals(sm.getAlgorithm(), algo);

	    assertNull(sm.getParameterSpec());
	    try {
		sm = factory.newSignatureMethod
		    (algo, new TestUtils.MyOwnSignatureMethodParameterSpec());
		fail("Should raise an IAPE for invalid parameters"); 
	    } catch (InvalidAlgorithmParameterException iape) {
	    } catch (Exception ex) {
		fail("Should raise an IAPE instead of " + ex);
	    }
	}

	try {
	    sm = factory.newSignatureMethod("non-existent", null); 
	    fail("Should raise an NSAE for non-existent algos"); 
	} catch (NoSuchAlgorithmException nsae) {}

	try {
	    sm = factory.newSignatureMethod(null, null); 
	    fail("Should raise a NPE for null algo"); 
	} catch (NullPointerException npe) {}
    } 
}

