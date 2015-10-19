package org.nci.soap.policy.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.WSSecurityUtil;
import org.doomdark.uuid.UUIDGenerator;
import org.nci.soap.security.util.SecurityInfo;
import org.nci.soap.security.util.WSSecurityContext;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class SecurityPolicyAnalyzer {

	static org.apache.commons.logging.Log log = 
	        org.apache.commons.logging.LogFactory.getLog(SecurityPolicyAnalyzer.class.getName());
	
	Document m_document;
	public SecurityPolicyAnalyzer(Document doc) {
		m_document = doc;
	}
	
	public void setAnalysedDocument(Document doc) {
		m_document = doc;
	}
	public Document getAnalysedDocument() {
		return m_document;
	}
	
	public Element getEnvelope()
	{
		log.trace("get Envelope!");
		
		Node rootElem = (Node)(m_document.getDocumentElement());
		
		while(rootElem.getNodeType() != Node.ELEMENT_NODE){
			rootElem = rootElem.getNextSibling();
		}
		
 		Element EnvelopeElem = WSSecurityUtil.findElement(rootElem, WSSecurityContext.ELEM_ENVELOPE, WSSecurityContext.URI_SOAP11_ENV);	
		return EnvelopeElem;
	}
	
	public Element getSecurityHeader(String actor) throws WSSecurityException {
		
		log.trace("get <security> if exist, or create it!");
		
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(m_document.getDocumentElement());
        Element soapHeaderElement = 
            getDirectChildElement(
            		m_document.getDocumentElement(), 
            		WSConstants.ELEM_HEADER, 
            		soapNamespace
            );
        if (soapHeaderElement == null) { // no SOAP header at all
            return null;
        }
        
        String actorLocal = WSConstants.ATTR_ACTOR;
        if (WSConstants.URI_SOAP12_ENV.equals(soapNamespace)) {
            actorLocal = WSConstants.ATTR_ROLE;
        }
        
        //
        // Iterate through the security headers
        //
        Element foundSecurityHeader = null;
        for (
            Node currentChild = soapHeaderElement.getFirstChild(); 
            currentChild != null; 
            currentChild = currentChild.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()
                && WSConstants.WSSE_LN.equals(currentChild.getLocalName())
                && WSConstants.WSSE_NS.equals(currentChild.getNamespaceURI())) {
                
                Element elem = (Element)currentChild;
                Attr attr = elem.getAttributeNodeNS(soapNamespace, actorLocal);
                String hActor = (attr != null) ? attr.getValue() : null;

                if (WSSecurityUtil.isActorEqual(actor, hActor)) {
                    if (foundSecurityHeader != null) {
                        if (log.isDebugEnabled()) {
                            log.debug(
                                "Two or more security headers have the same actor name: " + actor
                            );
                        }
                        throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
                    }
                    foundSecurityHeader = elem;
                }
            }
        }
        return foundSecurityHeader;
    }
	
	/**
     * Gets a direct child with specified localname and namespace. <p/>
     * 
     * @param parentNode the node where to start the search
     * @param localName local name of the child to get
     * @param namespace the namespace of the child to get
     * @return the node or <code>null</code> if not such node found
     */
    public static Element getDirectChildElement(
        Node parentNode, 
        String localName,
        String namespace
    ) {
        if (parentNode == null) {
            return null;
        }
        for (
            Node currentChild = parentNode.getFirstChild(); 
            currentChild != null; 
            currentChild = currentChild.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()
                && localName.equals(currentChild.getLocalName())
                && namespace.equals(currentChild.getNamespaceURI())) {
                return (Element)currentChild;
            }
        }
        return null;
    }
    
    public Element getSecurityContextToken(Element headerElem) throws WSSecurityException
	{
    	log.trace("get element <SecurityContextToken>!");
    	
		List<Element> elemList = WSSecurityUtil.findElements(headerElem, WSSecurityContext.WSC_LN, WSSecurityContext.WSC_NS);
		
		if(elemList.size() == 0)
			return null;
		else if(elemList.size() > 1){
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
		}
		
		return elemList.get(0);
	}
    
    public boolean getSecurityContextTokenInfo(Node SCTokenNode, Map<String,String> contextMap)
	{	
    	log.trace("get SecurityComtextToken info from element <SecurityContextToken>!");
    	
		if (SCTokenNode == null) {
            return false;
        }
        Node startParent = SCTokenNode;
        Node processedNode = null;

        while (SCTokenNode != null) {
            // start node processing at this point
            if (SCTokenNode.getNodeType() == Node.ELEMENT_NODE) {
                Element se = (Element) SCTokenNode;
                if (se.getChildNodes().getLength() == 1 
                		&& se.getFirstChild().getNodeType() == Node.TEXT_NODE){
                    if (contextMap.get(se.getLocalName()) == null) {
                    	contextMap.put(se.getLocalName(), se.getFirstChild().getNodeValue()); 
                    } else {
                        return false;
                    }
                }
            }
            processedNode = SCTokenNode;
            SCTokenNode = SCTokenNode.getFirstChild();

            // no child, this node is done.
            if (SCTokenNode == null) {
                // close node processing, get sibling
            	SCTokenNode = processedNode.getNextSibling();
            }
            // no more siblings, get parent, all children
            // of parent are processed.
            while (SCTokenNode == null) {
                processedNode = processedNode.getParentNode();
                if (processedNode == startParent) {
                    return true;
                }
                // close parent node processing (processed node now)
                SCTokenNode = processedNode.getNextSibling();
            }
        }
		return true;
	}
    
    public SecurityInfo judgeFullSecurityLevel(Element securityElem, String LocalName, String NameSpace)
	{
    	log.trace("get global encrypt level if exist!");
		
		List<Element> elemList = new ArrayList<Element>();
		elemList = WSSecurityUtil.findElements(securityElem, LocalName, NameSpace);
		
		SecurityInfo info = new SecurityInfo(0,0);
		
		if(elemList.size() != 1)
			return info;
		
		//格式检查
		String type = elemList.get(0).getAttribute("Type");
		if( type == "" || type == null)
			return info;
		
		String level = elemList.get(0).getTextContent();
		if( level == "" || level == null)
			return info;
		
		info.type = Integer.parseInt(type);
		info.level = Integer.parseInt(level);
		
		return info;
	}
	
	public boolean getSecurityPart(Element bodyElem, String LocalName, String NameSpace, String PartType, List<PartSecurityInfo> partList)
	{
		log.trace("get part encrypt info, include element, secret level, and element-id ...!");
		
		int COUNT_ENC = 0;
		int COUNT_SIG = 0;
		
		try{
			List<Element> elemList = new ArrayList<Element>();
			elemList = WSSecurityUtil.findElements(bodyElem, LocalName, NameSpace);
			if(elemList.size() == 0)
				return false;
			
			for(int i = 0; i < elemList.size(); i++){
				
				Element currElem = (Element)elemList.get(i);
				String attrValue = currElem.getAttribute("Type");
				if(PartType == WSSecurityContext.FLAG_ENC && (attrValue.equals("1") || attrValue.equals("3"))){
					
					PartSecurityInfo part = new PartSecurityInfo();
					
					UUIDGenerator m_uuidGenerator = null; 
					m_uuidGenerator = UUIDGenerator.getInstance();
					
					part.EncryptingNode = currElem.getParentNode();
					part.EncryptedNodeID = "ENC-" + m_uuidGenerator.generateRandomBasedUUID().toString();
					part.SecretLevel = Integer.parseInt(currElem.getTextContent());
					part.ContentFlag = false;
				
					partList.add(part);
					COUNT_ENC++;
				}
				else if(PartType == WSSecurityContext.FLAG_SIGN && (attrValue.equals("2") || attrValue.equals("3"))){
					
					PartSecurityInfo part = new PartSecurityInfo();
					
					UUIDGenerator m_uuidGenerator = null; 
					m_uuidGenerator = UUIDGenerator.getInstance();
					org.doomdark.uuid.UUID uuid = m_uuidGenerator.generateRandomBasedUUID();
					
					Element tmpParentElem = (Element) currElem.getParentNode();
					WSSecurityUtil.setNamespace(tmpParentElem, WSSecurityContext.WSU_NS, WSSecurityContext.WSU_PREFIX);
					tmpParentElem.setAttributeNS(WSSecurityContext.WSU_NS, "wsu:Id", "SIG-" + uuid.toString());
					
					part.EncryptingNodeID = "SIG-" + uuid.toString();
					part.EncryptingNode = tmpParentElem;
					part.SecretLevel = Integer.parseInt(currElem.getTextContent());
				
					partList.add(part);
					COUNT_SIG++;
				}	
			}
		}catch(Exception e){
			System.out.println("getEncryptedPart() Exception: " + e.getMessage());
		}
		
		if(PartType == WSSecurityContext.FLAG_ENC && COUNT_ENC == 0)
			return false;
		else if(PartType == WSSecurityContext.FLAG_SIGN && COUNT_SIG == 0)
			return false;
		else
			return true;
	}
}
