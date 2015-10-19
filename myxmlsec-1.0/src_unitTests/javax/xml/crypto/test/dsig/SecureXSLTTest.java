/*
 * Copyright 2006-2009 The Apache Software Foundation.
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
package javax.xml.crypto.test.dsig;

import java.io.*;
import java.security.Security;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.*;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.*;

import junit.framework.*;
import javax.xml.crypto.test.KeySelectors;

public class SecureXSLTTest extends TestCase {

    static {
        Security.insertProviderAt
            (new org.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public SecureXSLTTest(String name) {
	super(name);
    }

    public void test() throws Exception {

        String fs = System.getProperty("file.separator");
        String base = System.getProperty("basedir") == null ? "./": System.getProperty("basedir");
    	
        File baseDir = new File(base + fs + "data" 
	    + fs + "javax" + fs + "xml" + fs + "crypto", "dsig");

        String[] signatures =
            { "signature1.xml", "signature2.xml", "signature3.xml" };

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        File f = new File("doc.xml");
        for (int i=0; i<signatures.length; i++) {
	    String signature = signatures[i];
            // System.out.println("Validating " + signature);
            Document doc = dbf.newDocumentBuilder().parse
                (new FileInputStream(new File(baseDir, signature)));

            NodeList nl =
                doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                throw new Exception("Cannot find Signature element");
            }

            DOMValidateContext valContext = new DOMValidateContext
                (new KeySelectors.KeyValueKeySelector(), nl.item(0));
	    // enable reference caching in your validation context 
	    valContext.setProperty
    		("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);

            // make sure file is not left over from previous run
            f.delete();

            XMLSignature sig = fac.unmarshalXMLSignature(valContext);
            try {
                if (sig.validate(valContext)) {
                    System.err.println("Signature UNEXPECTEDLY passed validation");
                }
		sig.getSignedInfo().getReferences().get(0);
            } catch (XMLSignatureException xse) {
                // this is good, but still make sure attack was not successful
                // by falling through and checking if file was created
//		xse.printStackTrace();
            }
            if (f.exists()) {
                f.delete(); // cleanup file. comment out when debugging
                throw new Exception
                    ("Test FAILED: doc.xml was successfully created");
            }
        }
        // System.out.println("Test PASSED");
    }
}
