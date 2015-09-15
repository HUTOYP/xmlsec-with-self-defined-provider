package org.nci.xml.security.interfaces;

import java.util.List;

import org.nci.xml.security.contexts.*;
import org.w3c.dom.*;

public interface IXmlEncSign {

	public Document OpenXmlFile(String path);
	
	public long EncryptByName(Document doc, String eleName, ElementEncContext encArg) throws Exception;
	public long EncryptElement(Document doc, Element element, ElementEncContext encArg) throws Exception;
	public long EncryptElements(Document doc, List<Element> elements, ElementEncContext encArg);
	
	public long SignByName(Document doc, String eleName, ElementSignContext encArg);
	public long SignElement(Document doc, Element element, ElementSignContext encArg);
	public long SignElements(Document doc, List<Element> elements, ElementSignContext encArg);
	
	public Element GetResultElementIfNeed();
	
	public long SaveEncryptedFile(Document doc, String encFileName);
}
