package org.nci.soap.policy;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.ws.security.util.WSSecurityUtil;
import org.doomdark.uuid.UUIDGenerator;
import org.nci.soap.policy.analysis.PartSecurityInfo;
import org.nci.soap.security.util.SecurityInfo;
import org.nci.soap.security.util.WSSecurityContext;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SecurityPolicyInfo {
	
	private Document m_document;
	private Element m_securityHeaderElem;
	private Element m_securityContextTokenElem;
	
	private SecurityInfo m_securityInfo;
	
	private Map<String, String> m_contextMap;
	
	private List<PartSecurityInfo> m_partEncryptList;
	private List<PartSecurityInfo> m_partSignatureList;
	
	public void setSoapDocument(Document doc) {m_document = doc;}
	public Document getDocument() {return m_document;}
	
	public void setSecurityHeaderElem(Element securityHeaderElem) {m_securityHeaderElem = securityHeaderElem;}
	public Element getSecurityHeaderElem() {return m_securityHeaderElem;}
	
	public void setSecurityContextTokenElem(Element securityContextTokenElem) {m_securityContextTokenElem = securityContextTokenElem;}
	public Element getSecurityContextTokenElem() {return m_securityContextTokenElem;}
	
	public void setCipherContextMap(Map<String, String> contextMap) {m_contextMap = contextMap;}
	public Map<String, String> getCipherContextMap() {return m_contextMap;}
	
	public void setWholeSecurityInfo(SecurityInfo info) {m_securityInfo = info;}
	public SecurityInfo getWholeSecurityInfo() {return m_securityInfo;}
	
	public void setPartEncryptList(List<PartSecurityInfo> partList) {m_partEncryptList = partList;}
	public List<PartSecurityInfo> getPartEncryptList() {return m_partEncryptList;}
	public void setPartSignatureList(List<PartSecurityInfo> partList) {m_partSignatureList = partList;}
	public List<PartSecurityInfo> getPartSignatureList() {return m_partSignatureList;}
	
	public List<PartSecurityInfo> setWholeSignList(int level) {
		
		List<PartSecurityInfo> list_wholeSignPart = new ArrayList<PartSecurityInfo>();
		
		//get element timestamp
		Element elem = m_document.getDocumentElement();
		Element TSElem = WSSecurityUtil.findElement(elem, WSSecurityContext.TIMESTAMP_TOKEN_LN, WSSecurityContext.WSU_NS);
		
		//get element body
		Element bodyElem = WSSecurityUtil.findBodyElement(m_document);
		
		//UUID Generator
		UUIDGenerator m_uuidGenerator = UUIDGenerator.getInstance();
		
		String strID = "";

		//Timestamp
		if(TSElem != null){
			PartSecurityInfo TSEsigPart = new PartSecurityInfo();
			
			strID = "SIG-" + m_uuidGenerator.generateRandomBasedUUID().toString();

			WSSecurityUtil.setNamespace(TSElem, WSSecurityContext.WSU_NS, WSSecurityContext.WSU_PREFIX);
			TSElem.setAttributeNS(WSSecurityContext.WSU_NS, "wsu:Id", strID);
			
			TSEsigPart.EncryptingNodeID = strID;
			TSEsigPart.EncryptingNode= TSElem;
			TSEsigPart.SecretLevel = level;
			list_wholeSignPart.add(TSEsigPart);
		}
		
		//Body
		{
			PartSecurityInfo sigPart = new PartSecurityInfo();

			strID = "SIG-" + m_uuidGenerator.generateRandomBasedUUID().toString();
		
			WSSecurityUtil.setNamespace(bodyElem, WSSecurityContext.WSU_NS, WSSecurityContext.WSU_PREFIX);
			bodyElem.setAttributeNS(WSSecurityContext.WSU_NS, "wsu:Id", strID);
			
			sigPart.EncryptingNodeID = strID;
			sigPart.EncryptingNode = bodyElem;
			sigPart.SecretLevel = level;
			list_wholeSignPart.add(sigPart);
		}
		
		return list_wholeSignPart;
	}
	
	public PartSecurityInfo setWholeEncryptPart(int level) {
		
		PartSecurityInfo wholeEncryptPart = new PartSecurityInfo();
		
		Element bodyElem = WSSecurityUtil.findBodyElement(m_document);
		
		UUIDGenerator m_uuidGenerator = UUIDGenerator.getInstance();
		String strID = "ENC-" + m_uuidGenerator.generateRandomBasedUUID().toString();
		
		wholeEncryptPart.EncryptingNode = bodyElem;
		wholeEncryptPart.EncryptedNodeID = strID;
		wholeEncryptPart.SecretLevel = level;
		wholeEncryptPart.ContentFlag = true;
		 
		return wholeEncryptPart;
	}
}
