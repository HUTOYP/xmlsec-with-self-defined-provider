
/*
 * Copyright  1999-2009 The Apache Software Foundation.
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



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.signature.XMLSignatureInput;


/**
 * Unit test for {@link org.apache.xml.security.signature.XMLSignatureInput}
 *
 * @author Christian Geuer-Pollmann
 * @see <A HREF="http://nagoya.apache.org/bugzilla/show_bug.cgi?id=4336">Bug 4336</A>
 */
public class XMLSignatureInputTest extends TestCase {

   /** {@link org.apache.commons.logging} logging facility */
    static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(XMLSignatureInputTest.class.getName());

   /**
    * Method suite
    *
    *
    */
   public static Test suite() {
      return new TestSuite(XMLSignatureInputTest.class);
   }

   //J-
   static final String _octetStreamTextInput = "Kleiner Test";
   //J+

   /**
    * Constructor XMLSignatureInputTest
    *
    *
    * @param Name_
    *
    */
   public XMLSignatureInputTest(String Name_) {
      super(Name_);
   }

   /**
    * Method main
    *
    *
    * @param args
    *
    */
   public static void main(String[] args) {

      String[] testCaseName = { "-noloading",
                                XMLSignatureInputTest.class.getName() };

      junit.textui.TestRunner.main(testCaseName);
   }



   /**
    * Method testSetOctetStreamGetOctetStream
    *
    * @throws CanonicalizationException
    * @throws IOException
    * @throws InvalidCanonicalizerException
    */
   public static void testSetOctetStreamGetOctetStream()
           throws IOException, CanonicalizationException,
                  InvalidCanonicalizerException {

      InputStream inputStream =
         new ByteArrayInputStream(_octetStreamTextInput.getBytes("UTF-8"));
      XMLSignatureInput input = new XMLSignatureInput(inputStream);
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      InputStream res = input.getOctetStream();
      int off = 0;

      while (res.available() > 0) {
         byte array[] = new byte[1024];
         int len = res.read(array);

         baos.write(array, off, len);

         off += len;
      }

      byte resBytes[] = baos.toByteArray();
      String resString = new String(resBytes, "UTF-8");

      assertTrue(resString.equals(_octetStreamTextInput));
   }

   //J-
   static final String _nodeSetInput1 =
        "<?xml version=\"1.0\"?>\n"
      + "<!DOCTYPE doc [\n"
      + "<!ELEMENT doc (n+)>\n"
      + "<!ELEMENT n (#PCDATA)>\n"
      + "]>\n"
      + "<!-- full document with decl -->"
      + "<doc>"
      + "<n>1</n>"
      + "<n>2</n>"
      + "<n>3</n>"
      + "<n>4</n>"
      + "</doc>";
   // added one for xmlns:xml since Xalan 2.2.D11
   static final int _nodeSetInput1Nodes = 11; // was 10
   static final int _nodeSetInput1NodesWithComments = _nodeSetInput1Nodes + 1;
   //J+
   //J-
   static final String _nodeSetInput2 =
        "<?xml version=\"1.0\"?>\n"
      + "<!-- full document -->"
      + "<doc>"
      + "<n>1</n>"
      + "<n>2</n>"
      + "<n>3</n>"
      + "<n>4</n>"
      + "</doc>";
   // added one for xmlns:xml since Xalan 2.2.D11
   static final int _nodeSetInput2Nodes = 11; // was 10
   static final int _nodeSetInput2NodesWithComments = _nodeSetInput2Nodes + 1;
   //J+
   //J-
   static final String _nodeSetInput3 =
        "<!-- document -->"
      + "<doc>"
      + "<n>1</n>"
      + "<n>2</n>"
      + "<n>3</n>"
      + "<n>4</n>"
      + "</doc>";
   // added one for xmlns:xml since Xalan 2.2.D11
   static final int _nodeSetInput3Nodes = 11; // was 10
   static final int _nodeSetInput3NodesWithComments = _nodeSetInput3Nodes + 1;
   //J+


   /**
    * Method testIsInitialized
    *
    * @throws IOException
    */
   public static void testIsInitializedWithOctetStream() throws IOException {

      InputStream inputStream =
         new ByteArrayInputStream(_octetStreamTextInput.getBytes());
      XMLSignatureInput input = new XMLSignatureInput(inputStream);

      assertTrue("Input is initialized", input.isInitialized());
   }

   /**
    * Method testOctetStreamIsOctetStream
    *
    * @throws IOException
    */
   public static void testOctetStreamIsOctetStream() throws IOException {

      InputStream inputStream =
         new ByteArrayInputStream(_octetStreamTextInput.getBytes());
      XMLSignatureInput input = new XMLSignatureInput(inputStream);

      assertTrue("Input is octet stream", input.isOctetStream());
   }

   /**
    * Method testOctetStreamIsNotNodeSet
    *
    * @throws IOException
    */
   public static void testOctetStreamIsNotNodeSet() throws IOException {

      InputStream inputStream =
         new ByteArrayInputStream(_octetStreamTextInput.getBytes());
      XMLSignatureInput input = new XMLSignatureInput(inputStream);

      assertTrue("Input is not node set", !input.isNodeSet());
   }

   static {
      org.apache.xml.security.Init.init();
   }
}
