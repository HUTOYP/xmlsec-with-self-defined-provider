/*
 * Copyright 2008-2009 The Apache Software Foundation.
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
package org.apache.xml.security.test.signature;

import java.io.File;
import java.io.FileInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class NoKeyInfoTest extends TestCase {

    private static final String BASEDIR = System.getProperty("basedir");
    private static final String SEP = System.getProperty("file.separator");

    private DocumentBuilder db;

    public NoKeyInfoTest(String name) {
	super(name);
    }

    public static Test suite() {
        TestSuite suite = new TestSuite(NoKeyInfoTest.class);
        return suite;
    }

    public void setUp() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        db = dbf.newDocumentBuilder();
    }


    public void testNullKeyInfo() throws Exception {
	File f = null;
        if (BASEDIR != null && !"".equals(BASEDIR)) {
            f = new File(BASEDIR + SEP +
                  "data/ie/baltimore/merlin-examples/merlin-xmldsig-twenty-three/signature-enveloping-hmac-sha1.xml");
        } else {
            f = new File(
                  "data/ie/baltimore/merlin-examples/merlin-xmldsig-twenty-three/signature-enveloping-hmac-sha1.xml");
        }
	Document doc = db.parse(new FileInputStream(f));
	NodeList nl = doc.getElementsByTagNameNS
	    (Constants.SignatureSpecNS, "Signature");
	XMLSignature sig = new XMLSignature
	    ((Element) nl.item(0), f.toURL().toString());
	KeyInfo ki = sig.getKeyInfo();
	assertNull(ki);
    }
}
