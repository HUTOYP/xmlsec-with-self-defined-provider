/*
 * Copyright 2009 The Apache Software Foundation.
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
package org.apache.xml.security.test.utils.resolver;

import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.TestCase;

import org.apache.xml.security.Init;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class ResolverDirectHTTP extends TestCase {
  public void testBug40783() throws Exception{
	  Init.init();
	  Document doc=DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();		
	  Attr uri=doc.createAttribute("id");
	  uri.setNodeValue("urn:ddd:uuu");
	  ((Element)doc.createElement("test")).setAttributeNode(uri);
	  try {
		  ResourceResolver resolver=ResourceResolver.getInstance(uri, null);		  
		  fail("No exception throw, but resolver found:"+resolver);
	  } catch (ResourceResolverException e) {
		  
	  }
	}
  
}
