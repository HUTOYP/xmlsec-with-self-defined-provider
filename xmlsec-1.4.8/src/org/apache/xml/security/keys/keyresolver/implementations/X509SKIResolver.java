
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
package org.apache.xml.security.keys.keyresolver.implementations;



import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;


import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.x509.XMLX509SKI;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.keys.keyresolver.KeyResolverSpi;
import org.apache.xml.security.keys.storage.StorageResolver;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;


/**
 *
 *
 * @author $Author: coheigea $
 */
public class X509SKIResolver extends KeyResolverSpi {

   /** {@link org.apache.commons.logging} logging facility */
    static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(X509SKIResolver.class.getName());

   
   /**
    * Method engineResolvePublicKey
    *
    * @param element
    * @param BaseURI
    * @param storage
    * @return null if no {@link PublicKey} could be obtained
    * @throws KeyResolverException
    */
   public PublicKey engineLookupAndResolvePublicKey(
           Element element, String BaseURI, StorageResolver storage)
              throws KeyResolverException {

      X509Certificate cert = this.engineLookupResolveX509Certificate(element,
                                BaseURI, storage);

      if (cert != null) {
         return cert.getPublicKey();
      }

      return null;
   }

   /**
    * Method engineResolveX509Certificate
    * @inheritDoc
    * @param element
    * @param BaseURI
    * @param storage
    *
    * @throws KeyResolverException
    */
   public X509Certificate engineLookupResolveX509Certificate(
           Element element, String BaseURI, StorageResolver storage)
              throws KeyResolverException {
	   if (log.isDebugEnabled()) {
	     log.debug("Can I resolve " + element.getTagName() + "?");
	   }	      
	   if (!XMLUtils.elementIsInSignatureSpace(element,
              Constants._TAG_X509DATA)) {
	         log.debug("I can't");
	         return null;
	   }
	   /** Field _x509childObject[] */
	   XMLX509SKI x509childObject[] = null;
	   
	   Element x509childNodes[] = null;
	   x509childNodes = XMLUtils.selectDsNodes(element.getFirstChild(),
	                  Constants._TAG_X509SKI);

	   if (!((x509childNodes != null)
	                 && (x509childNodes.length > 0))) {
		   log.debug("I can't");
	        return null;
	   }
	   try {         
         if (storage == null) {
            Object exArgs[] = { Constants._TAG_X509SKI };
            KeyResolverException ex =
               new KeyResolverException("KeyResolver.needStorageResolver",
                                        exArgs);

            log.info("", ex);

            throw ex;
         }

         x509childObject = new XMLX509SKI[x509childNodes.length];

         for (int i = 0; i < x509childNodes.length; i++) {
            x509childObject[i] =
               new XMLX509SKI(x509childNodes[i], BaseURI);
         }

         Iterator storageIterator = storage.getIterator();
         while (storageIterator.hasNext()) {
            X509Certificate cert = (X509Certificate)storageIterator.next();
            XMLX509SKI certSKI = new XMLX509SKI(element.getOwnerDocument(), cert);

            for (int i = 0; i < x509childObject.length; i++) {
               if (certSKI.equals(x509childObject[i])) {
                  log.debug("Return PublicKey from "
                            + cert.getSubjectDN().getName());

                  return cert;
               }
            }
         }
      } catch (XMLSecurityException ex) {
         throw new KeyResolverException("empty", ex);
      }

      return null;
   }

   /**
    * Method engineResolveSecretKey
    * @inheritDoc
    * @param element
    * @param BaseURI
    * @param storage
    *
    */
   public javax.crypto.SecretKey engineLookupAndResolveSecretKey(
           Element element, String BaseURI, StorageResolver storage)
    {
      return null;
   }
}
