/*
 * Copyright  2010 The Apache Software Foundation.
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
package org.apache.xml.security.test.keys.keyresolver;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.KeyResolver;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.keys.keyresolver.KeyResolverSpi;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

/**
 * KeyResolver test.
 */
public class KeyResolverTest extends TestCase {

    public KeyResolverTest() {
        super("KeyResolverTest");
    }

    public KeyResolverTest(String name) {
        super(name);
        org.apache.xml.security.Init.init();
    }

    public static Test suite() {
        return new TestSuite(KeyResolverTest.class);
    }

    /**
     * Encrypt some data, embedded the data encryption key
     * in the message using the key transport algorithm rsa-1_5.
     * Decrypt the data by resolving the Key Encryption Key.
     * This test verifies if a KeyResolver can return a PrivateKey.
     */
    public void testResolvePrivateKey() throws Exception {
        // See if AES-128 is available...
        String algorithmId = 
            JCEMapper.translateURItoJCEID(
                    org.apache.xml.security.utils.EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128
                );
        boolean haveAES = false;
        if (algorithmId != null) {
            try {
                if (Cipher.getInstance(algorithmId) != null) {
                    haveAES = true;
                }
            } catch (NoSuchAlgorithmException nsae) {
            } catch (NoSuchPaddingException nspe) {
            }
        }
        
        if (!haveAES) {
            return;
        }
        
        // Create a sample XML document
        DocumentBuilderFactory fac = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = fac.newDocumentBuilder();
        Document document = builder.newDocument();

        Element rootElement = document.createElement("root");
        document.appendChild(rootElement);
        Element elem = document.createElement("elem");
        Text text = document.createTextNode("text");
        elem.appendChild(text);
        rootElement.appendChild(elem);

        // Create a data encryption key
        byte[] keyBytes = { 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7 };
        SecretKeySpec dataEncryptKey = new SecretKeySpec(keyBytes, "AES");

        // Create public and private keys
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
                new BigInteger(
                    "8710a2bcb2f3fdac177f0ae0461c2dd0ebf72e0d88a5400583a7d8bdabd6" +
                    "ae009d30cfdf6acb5b6a64cdc730bc630a39d946d08babffe62ea20a87e37c93b3b0e8a8e576045b" +
                    "bddfbde83ca9bfa180fe6a5f5eee60661936d728314e809201ef52cd71d9fa3c8ce83f9d30ab5e08" +
                    "1539219e7e45dd6a60be65ac95d2049b8f21", 16),
                new BigInteger("10001", 16));
        
        RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(
                new BigInteger(
                    "8710a2bcb2f3fdac177f0ae0461c2dd0ebf72e0d88a5400583a7d8bdabd" +
                    "6ae009d30cfdf6acb5b6a64cdc730bc630a39d946d08babffe62ea20a87e37c93b3b0e8a8e576045" +
                    "bbddfbde83ca9bfa180fe6a5f5eee60661936d728314e809201ef52cd71d9fa3c8ce83f9d30ab5e0" +
                    "81539219e7e45dd6a60be65ac95d2049b8f21", 16),
                new BigInteger(
                    "20c39e569c2aa80cc91e5e6b0d56e49e5bbf78827bf56a546c1d996c597" +
                    "5187cb9a50fa828e5efe51d52f5d112c20bc700b836facadca6e0051afcdfe866841e37d207c0295" +
                    "36ff8674b301e2198b2c56abb0a0313f8ff84c1fcd6fa541aa6e5d9c018fab4784d2940def5dc709" +
                    "ddc714d73b6c23b5d178eaa5933577b8e8ae9", 16));
        
        RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
        RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);

        // Encrypt the data encryption key with the key encryption key
        XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
        keyCipher.init(XMLCipher.WRAP_MODE, pubKey);
        EncryptedKey encryptedKey = keyCipher.encryptKey(document, dataEncryptKey);
        
        String keyName = "testResolvePrivateKey";
        KeyInfo kekInfo = new KeyInfo(document);
        kekInfo.addKeyName(keyName);
        encryptedKey.setKeyInfo(kekInfo);

        // Encrypt the data
        XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_128);
        xmlCipher.init(XMLCipher.ENCRYPT_MODE, dataEncryptKey);

        EncryptedData encryptedData = xmlCipher.getEncryptedData();
        KeyInfo keyInfo = new KeyInfo(document);
        keyInfo.add(encryptedKey);
        encryptedData.setKeyInfo(keyInfo);

        xmlCipher.doFinal(document, rootElement, true);

        Element encryptedDataElement = (Element) rootElement.getFirstChild();
        assertEquals("EncryptedData", encryptedDataElement.getLocalName());

        // Register a KeyResolver for the PrivateKey
        MyPrivateKeyResolver.pk = privKey;
        MyPrivateKeyResolver.pkName = keyName;
        KeyResolver.registerAtStart(MyPrivateKeyResolver.class.getName());
        KeyResolverSpi resolver = (KeyResolverSpi)KeyResolver.iterator().next();
        assertEquals(MyPrivateKeyResolver.class.getName(), resolver.getClass().getName());

        // Decrypt the data by resolving the private key used as the KEK
        XMLCipher decryptCipher = XMLCipher.getInstance();
        decryptCipher.init(XMLCipher.DECRYPT_MODE, null);
        decryptCipher.doFinal(document, encryptedDataElement);

        Element decryptedElement = (Element) rootElement.getFirstChild();
        assertEquals("elem", decryptedElement.getLocalName());
    }

    // A KeyResolver that returns a PrivateKey for a specific KeyName.
    public static class MyPrivateKeyResolver extends KeyResolverSpi {
        
        // We use static variables because KeyResolver.register() demands
        // the use of the default constructor.
        private static PrivateKey pk;
        private static String pkName;
        
        public boolean engineCanResolve(Element element, String BaseURI,
                StorageResolver storage) {
            return false;
        }

        public PrivateKey engineLookupAndResolvePrivateKey(Element element,
                String BaseURI, StorageResolver storage)
                throws KeyResolverException {

            if (Constants.SignatureSpecNS.equals(element.getNamespaceURI()) && 
                    Constants._TAG_KEYNAME.equals(element.getLocalName())) {
                String keyName = element.getFirstChild().getNodeValue();
                if (pkName.equals(keyName)) {
                    return pk;
                }
            }
            
            return null;
        }
    }
}
