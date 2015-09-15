package org.nci.soap.security.util;

import org.nci.xml.security.util.XmlCipherUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class ProxyConfig {

	private static String ELEM_PMETHOD = "ProxyMethod";
	private static String ELEM_PHOST = "ProxyHost";
	private static String ELEM_PPORT = "ProxyPort";
	private static String ELEM_MMJID = "MMJID";
	private static String ATTR_LHOST = "RemoteHost";
	private static String ATTR_LPORT = "RemotePort";
	
	private static ProxyConfig m_instance = null;
	Document m_document = null;
	Element m_rootElem = null;
	
	public static ProxyConfig getInstance(String file)
	{
		if(m_instance == null)
			m_instance = new ProxyConfig(file);
		
		return m_instance;
	}
	
	private ProxyConfig(String file) {
		
		m_document = XmlCipherUtil.ImportXmlFile(file);
		m_rootElem = m_document.getDocumentElement();
	}
	
	public ProxyStruct findProxyConfig(String remoteHost, String remotePort) {
	
		ProxyStruct proxy = new ProxyStruct();
		if(m_rootElem != null)
		{
			for (
		            Node currentChild = m_rootElem.getFirstChild(); 
		            currentChild != null; 
		            currentChild = currentChild.getNextSibling()
		        ){
					if(currentChild.getNodeType() == Node.ELEMENT_NODE 
							&& currentChild.getLocalName().equals(ELEM_PMETHOD))
					{
						Element currentElem = (Element)currentChild;
						if(currentElem.getAttribute(ATTR_LHOST).equals(remoteHost)
								&& currentElem.getAttribute(ATTR_LPORT).equals(remotePort))
						{
							proxy.ProxyHost = getDirectChildElement(currentElem, ELEM_PHOST).getTextContent();
							proxy.ProxyPort = getDirectChildElement(currentElem, ELEM_PPORT).getTextContent();
							proxy.MMJID = getDirectChildElement(currentElem, ELEM_MMJID).getTextContent();
							
							break;
						}
					}
			}
			return proxy;
		}
		return null;
	}
	
	public Element getDirectChildElement(Node parentNode, String localName) {
        
		if (parentNode == null) {
            return null;
        }
        for (
            Node currentChild = parentNode.getFirstChild(); 
            currentChild != null; 
            currentChild = currentChild.getNextSibling()) 
        {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()
                && localName.equals(currentChild.getLocalName())) {
                return (Element)currentChild;
            }
        }
        return null;
    }
}
