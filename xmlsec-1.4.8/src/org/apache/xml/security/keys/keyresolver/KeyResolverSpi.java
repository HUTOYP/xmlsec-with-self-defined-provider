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
package org.apache.xml.security.keys.keyresolver;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import javax.crypto.SecretKey;

import org.apache.xml.security.keys.storage.StorageResolver;
import org.w3c.dom.Element;

/**
 * This class is abstract class for a child KeyInfo Elemnet.
 *
 * If you want the your KeyResolver, at firstly you must extand this class, and register
 * as following in config.xml
 * <PRE>
 *  &lt;KeyResolver URI="http://www.w3.org/2000/09/xmldsig#KeyValue"
 *   JAVACLASS="MyPackage.MyKeyValueImpl"//gt;
 * </PRE>
 *
 * @author $Author: coheigea $
 * @version $Revision: 1003198 $
 */
public abstract class KeyResolverSpi {
   /**
    * This method returns whether the KeyResolverSpi is able to perform the requested action.
    *
    * @param element
    * @param BaseURI
    * @param storage
    * @return
    */
   public boolean engineCanResolve(Element element, String BaseURI,
	                                            StorageResolver storage) {
	   throw new UnsupportedOperationException();
   }

   /**
    * Method engineResolvePublicKey
    *
    * @param element
    * @param BaseURI
    * @param storage
    * @return resolved public key from the registered from the element.
    * 
    * @throws KeyResolverException
    */
   public PublicKey engineResolvePublicKey(
      Element element, String BaseURI, StorageResolver storage)
         throws KeyResolverException {
      	   throw new UnsupportedOperationException();
    };
       
   /**
    * Method engineLookupAndResolvePublicKey
    *
    * @param element
    * @param BaseURI
    * @param storage
    * @return resolved public key from the registered from the element.
    * 
    * @throws KeyResolverException
    */
    public PublicKey engineLookupAndResolvePublicKey(
      Element element, String BaseURI, StorageResolver storage)
         throws KeyResolverException {
    	KeyResolverSpi tmp = cloneIfNeeded();
    	if (!tmp.engineCanResolve(element, BaseURI, storage))
	    	return null;
	    return tmp.engineResolvePublicKey(element, BaseURI, storage);
    }

    private KeyResolverSpi cloneIfNeeded() throws KeyResolverException {
    	KeyResolverSpi tmp=this;    
    	if (globalResolver) {
    		try {
    			tmp = (KeyResolverSpi) getClass().newInstance();    	    
    		} catch (InstantiationException e) {
    			throw new KeyResolverException("",e);
    		} catch (IllegalAccessException e) {
    			throw new KeyResolverException("",e);
    		}
    	}
    	return tmp;
    }

    /**
     * Method engineResolveCertificate
     *
     * @param element
     * @param BaseURI
     * @param storage
     * @return resolved X509Certificate key from the registered from the elements
     *
     * @throws KeyResolverException
     */
    public X509Certificate engineResolveX509Certificate(
       Element element, String BaseURI, StorageResolver storage)
          throws KeyResolverException{
         	   throw new UnsupportedOperationException();
    };
    
   /**
    * Method engineLookupResolveX509Certificate
    *
    * @param element
    * @param BaseURI
    * @param storage
    * @return resolved X509Certificate key from the registered from the elements
    *
    * @throws KeyResolverException
    */
    public X509Certificate engineLookupResolveX509Certificate(
      Element element, String BaseURI, StorageResolver storage)
         throws KeyResolverException {
    	KeyResolverSpi tmp = cloneIfNeeded();
    	if (!tmp.engineCanResolve(element, BaseURI, storage))
    		return null;
    	return tmp.engineResolveX509Certificate(element, BaseURI, storage);
    	
    }
    /**
     * Method engineResolveSecretKey
     *
     * @param element
     * @param BaseURI
     * @param storage
     * @return resolved SecretKey key from the registered from the elements
     *
     * @throws KeyResolverException
     */
    public SecretKey engineResolveSecretKey(
       Element element, String BaseURI, StorageResolver storage)
          throws KeyResolverException{
        	   throw new UnsupportedOperationException();
    }; 
    
   /**
    * Method engineLookupAndResolveSecretKey
    *
    * @param element
    * @param BaseURI
    * @param storage
    * @return resolved SecretKey key from the registered from the elements
    *
    * @throws KeyResolverException
    */
   public SecretKey engineLookupAndResolveSecretKey(
      Element element, String BaseURI, StorageResolver storage)
         throws KeyResolverException {
	   KeyResolverSpi tmp = cloneIfNeeded();
	   if (!tmp.engineCanResolve(element, BaseURI, storage))
		   return null;
   		return tmp.engineResolveSecretKey(element, BaseURI, storage);   		
   }
   
   /**
    * Method engineLookupAndResolvePrivateKey
    *
    * @param element
    * @param BaseURI
    * @param storage
    * @return resolved PrivateKey key from the registered from the elements
    *
    * @throws KeyResolverException
    */
   public PrivateKey engineLookupAndResolvePrivateKey(
      Element element, String BaseURI, StorageResolver storage)
         throws KeyResolverException {
       // This method was added later, it has no equivalent
       // engineResolvePrivateKey() in the old API.
       // We cannot throw UnsupportedOperationException because
       // KeyResolverSpi implementations who don't know about
       // this method would stop the search too early.
       return null;
   }

   /** Field _properties */
   protected java.util.Map _properties = null;
   
   protected boolean globalResolver=false;

   /**
    * Method engineSetProperty
    *
    * @param key
    * @param value
    */
   public void engineSetProperty(String key, String value) {     
	   if (_properties==null)
		   _properties=new HashMap();
      this._properties.put(key, value);
   }

   /**
    * Method engineGetProperty
    *
    * @param key
    * @return obtain the property appointed by key
    */
   public String engineGetProperty(String key) {
	   if (_properties==null)
		   return null;
      
      return (String) this._properties.get(key);
   }

   /**
    * Method understandsProperty
    *
    * @param propertyToTest
    * @return true if understood the property
    */
   public boolean understandsProperty(String propertyToTest) {
	   if (_properties==null)
		   return false;
      
      return  this._properties.get(propertyToTest)!=null;
   }
   public void setGlobalResolver(boolean globalResolver) {
	this.globalResolver = globalResolver;
   }
      
}
