/*
 * Copyright  1999-2010 The Apache Software Foundation.
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

import java.io.InputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.resolver.implementations.ResolverXPointer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class SignatureTest extends TestCase {
    public final static String DS_NS = "http://www.w3.org/2000/09/xmldsig#";

    private static final String BASEDIR = 
        System.getProperty("basedir") == null ? "./": System.getProperty("basedir");
    public final static String KEYSTORE_DIRECTORY = BASEDIR + "/data/";
    public final static String KEYSTORE_PASSWORD_STRING = "changeit";
    public final static char[] KEYSTORE_PASSWORD = KEYSTORE_PASSWORD_STRING
			.toCharArray();

    public SignatureTest(String test) {
        super(test);
    }

    public static Test suite() {
       return new TestSuite(SignatureTest.class);
    }

    /**
     * Loads the 'localhost' keystore from the test keystore.
     * 
     * @return test keystore.
     * @throws Exception
     */
    public KeyStore getKeyStore() throws Exception {
	KeyStore ks = KeyStore.getInstance("JKS");
	InputStream ksis = new FileInputStream(KEYSTORE_DIRECTORY + "test.jks");
	ks.load(ksis, KEYSTORE_PASSWORD);
	ksis.close();
	return ks;
    }

    public PublicKey getPublicKey() throws Exception {
	KeyStore keyStore = getKeyStore();
	Enumeration aliases = keyStore.aliases();
	while (aliases.hasMoreElements()) {
	    String alias = (String) aliases.nextElement();
	    if (keyStore.isKeyEntry(alias)) {
		return keyStore.getCertificate(alias).getPublicKey();
	    }
	}
	return null;
    }

    public PrivateKey getPrivateKey() throws Exception {
	KeyStore keyStore = getKeyStore();
	Enumeration aliases = keyStore.aliases();
	while (aliases.hasMoreElements()) {
 	    String alias = (String) aliases.nextElement();
	    if (keyStore.isKeyEntry(alias)) {
		return (PrivateKey) keyStore.getKey(alias, KEYSTORE_PASSWORD);
	    }
	}
	return null;
    }

    public Document getOriginalDocument() throws Throwable {
	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	dbf.setNamespaceAware(true);
	DocumentBuilder db = dbf.newDocumentBuilder();
	Document doc = db.newDocument();

	Element rootElement = doc.createElementNS("http://ns.example.org/",
			"root");
        rootElement.appendChild(doc.createTextNode("Hello World!"));
	doc.appendChild(rootElement);

	return doc;
    }

    public XMLSignature signDocument(Document doc) throws Throwable {
	XMLSignature sig = new XMLSignature(doc, "",
		XMLSignature.ALGO_ID_SIGNATURE_DSA);
	Element root = doc.getDocumentElement();
	root.appendChild(sig.getElement());

	sig.getSignedInfo().addResourceResolver(new ResolverXPointer());

	Transforms transforms = new Transforms(doc);
	transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
	transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
	sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

	sig.addKeyInfo(getPublicKey());
	sig.sign(getPrivateKey());

	// displayDocument(doc);

	return sig;
    }

    public void setUp() throws Exception {
	Init.init();
	Constants.setSignatureSpecNSprefix("ds");
    }

    public void displayOriginalDocument() throws Throwable {
	// displayDocument(getOriginalDocument());
    }

    public void testSigning() throws Throwable {
	signDocument(getOriginalDocument());
    }

    public void testSigningVerifyingFromRebuildSignature() throws Throwable {
	Document doc = getOriginalDocument();
	signDocument(doc);
	Element signatureElem = (Element) doc.getElementsByTagNameNS(DS_NS,
			"Signature").item(0);
	XMLSignature signature = new XMLSignature(signatureElem, "");

	PublicKey pubKey = getPublicKey();

	assertTrue(signature.checkSignatureValue(pubKey));
    }

    public void testSigningVerifyingFromExistingSignature() throws Throwable {
	Document doc = getOriginalDocument();
	XMLSignature signature = signDocument(doc);

	PublicKey pubKey = getPublicKey();
	assertTrue(signature.checkSignatureValue(pubKey));
    }

    public void testSigningVerifyingFromExistingSignatureSameThread()
	throws Throwable {
	Document doc = getOriginalDocument();
	XMLSignature signature = signDocument(doc);

	PublicKey pubKey = getPublicKey();
		
	VerifyingRunnable r = new VerifyingRunnable(signature, pubKey);
	r.run();
	if (r.throwable != null) {
	    throw r.throwable;
	}
	assertTrue(r.result);
    }
	
    public void testSigningVerifyingFromExistingSignatureSeparateThread()
	throws Throwable {
	Document doc = getOriginalDocument();
	XMLSignature signature = signDocument(doc);

	PublicKey pubKey = getPublicKey();
	VerifyingRunnable r = new VerifyingRunnable(signature, pubKey);
	Thread t = new Thread(r);
	t.start();
	t.join();
	if (r.throwable != null) {
	    throw r.throwable;
	}
	assertTrue(r.result);
    }

    public static class VerifyingRunnable implements Runnable {
	public volatile Throwable throwable;
	public volatile boolean result;
	private XMLSignature signature;
	private PublicKey pubKey;

	public VerifyingRunnable(XMLSignature signature, PublicKey pubKey) {
	    this.signature = signature;
	    this.pubKey = pubKey;
	}

	public void run() {
	    try {
		result = signature.checkSignatureValue(pubKey);
	    } catch (XMLSignatureException e) {
		throwable = e;
	    }
	}
    }
}
