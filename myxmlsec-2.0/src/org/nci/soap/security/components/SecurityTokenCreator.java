package org.nci.soap.security.components;

import javax.xml.namespace.QName;

import org.apache.xml.security.utils.Base64;
import org.nci.soap.security.util.WSSecurityContext;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SecurityTokenCreator {
	public static final QName TOKEN_BST = new QName(WSSecurityContext.WSSE_NS, WSSecurityContext.BINARY_TOKEN_LN);
	public static final QName TOKEN_KI = new QName(WSSecurityContext.WSSE_NS, WSSecurityContext.TOKEN_KI);

	private Element element = null;
	private BinaryDigitalCert cinfo = null;
	
	boolean isNeedAttribute = false;

	//Set or Get a CertInformation
	public BinaryDigitalCert getCinfo() { return cinfo; }
	public void setCinfo(BinaryDigitalCert cinfo) {	this.cinfo = cinfo; }

	//Need attribute info if it is true
	public boolean isNeedAttribute() { return isNeedAttribute; }
	public void setNeedAttribute(boolean isNeedAttribute) {	this.isNeedAttribute = isNeedAttribute; }
	
	//build binary security token
	public Element Build(Document doc){
	
		element = doc.createElementNS(WSSecurityContext.WSSE_NS, 
				WSSecurityContext.WSSE_PREFIX + ":" + WSSecurityContext.BINARY_TOKEN_LN);
    	
    	element.appendChild(doc.createTextNode(Base64.encode(cinfo.getByteData())));
    	
    	element.setAttributeNS(WSSecurityContext.WSU_NS, WSSecurityContext.WSU_PREFIX + ":Id", cinfo.getCertID());
    	element.setAttributeNS(null, "ValueType", cinfo.getCertValueType());	
    	element.setAttributeNS(null, "EncodingType", cinfo.getCertEncodingType());
		
		return element;
	}
}
