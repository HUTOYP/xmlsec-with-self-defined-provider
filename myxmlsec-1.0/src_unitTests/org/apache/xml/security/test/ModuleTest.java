/*
 * Copyright  2004-2010 The Apache Software Foundation.
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
package org.apache.xml.security.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;


public class ModuleTest extends TestCase {

   /** {@link org.apache.commons.logging} logging facility */
    static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(ModuleTest.class.getName());

   public ModuleTest(String test) {
      super(test);
   }

   /**
    * Method suite
    *
    *
    */

   public static Test suite() {

      TestSuite suite =
         new TestSuite("All org.apache.xml.security.test JUnit Tests");

      //J-
      suite.addTest(org.apache.xml.security.test.c14n.helper.C14nHelperTest.suite());
      suite.addTest(org.apache.xml.security.test.c14n.helper.AttrCompareTest.suite());
      suite.addTest(org.apache.xml.security.test.c14n.implementations.Canonicalizer20010315Test.suite());
      suite.addTest(org.apache.xml.security.test.c14n.implementations.Canonicalizer20010315ExclusiveTest.suite());
      suite.addTest(org.apache.xml.security.test.c14n.implementations.ExclusiveC14NInterop.suite());
      suite.addTest(org.apache.xml.security.test.c14n.implementations.Canonicalizer11Test.suite());
      suite.addTest(org.apache.xml.security.test.c14n.implementations.Bug45961Test.suite());
      suite.addTest(org.apache.xml.security.test.c14n.implementations.Santuario191Test.suite());
      suite.addTest(org.apache.xml.security.test.c14n.implementations.Santuario273Test.suite());
      suite.addTest(org.apache.xml.security.test.external.org.apache.xalan.XPathAPI.XalanBug1425Test.suite());
      suite.addTest(org.apache.xml.security.test.external.org.apache.xalan.XPathAPI.AttributeAncestorOrSelfTest.suite());
      suite.addTest(org.apache.xml.security.test.signature.AllTests.suite());      
      suite.addTest(org.apache.xml.security.test.utils.AllTests.suite());
      suite.addTest(org.apache.xml.security.c14n.implementations.AllTests.suite());
      suite.addTest(org.apache.xml.security.test.transforms.implementations.AllTests.suite());
      suite.addTest(org.apache.xml.security.test.transforms.RegisterTest.suite());
      suite.addTest(org.apache.xml.security.test.algorithms.AllTests.suite());
      suite.addTest(org.apache.xml.security.test.keys.keyresolver.KeyResolverTest.suite());
      suite.addTest(org.apache.xml.security.test.keys.content.x509.XMLX509SKITest.suite());
      suite.addTest(org.apache.xml.security.test.keys.content.x509.XMLX509IssuerSerialTest.suite());
      suite.addTest(org.apache.xml.security.test.keys.content.x509.XMLX509CertificateTest.suite());
      suite.addTest(org.apache.xml.security.test.keys.storage.KeyStoreResolverTest.suite());
      suite.addTest(org.apache.xml.security.test.keys.storage.StorageResolverTest.suite());
      suite.addTest(org.apache.xml.security.test.version.VersionTest.suite());
      // suite.addTest(org.apache.xml.security.test.algorithms.implementations.KeyWrapTest.suite());
      // suite.addTest(org.apache.xml.security.test.algorithms.implementations.BlockEncryptionTest.suite());
      //J+

      return suite;
   }

   /**
    * Method main
    *
    * @param args
    */
   public static void main(String[] args) {

      //XMLUtils.spitOutVersions(log);

      boolean useTextUI = true;

      if (useTextUI) {
         junit.textui.TestRunner.run(suite());
      } else {
         try {
            String lookAndFeelClass =
               "com.incors.plaf.kunststoff.KunststoffLookAndFeel";
            javax.swing.LookAndFeel lnf =
               (javax.swing.LookAndFeel) Class.forName(lookAndFeelClass)
                  .newInstance();

            javax.swing.UIManager.setLookAndFeel(lnf);
         } catch (Exception ex) {}

         //junit.swingui.TestRunner.main(testCaseName);
         junit.textui.TestRunner.run(suite());
      }
   }

   static {
      org.apache.xml.security.Init.init();
   }

}
