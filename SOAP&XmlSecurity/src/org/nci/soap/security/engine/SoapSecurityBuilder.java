package org.nci.soap.security.engine;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.WSSecurityUtil;
import org.nci.csp.CSP;
import org.nci.soap.policy.SecurityPolicyInfo;
import org.nci.soap.policy.analysis.PartSecurityInfo;
import org.nci.soap.security.components.BinaryDigitalCert;
import org.nci.soap.security.components.SecurityTokenCreator;
import org.nci.soap.security.components.TimestampCreator;
import org.nci.soap.security.exception.WSAccessException;
import org.nci.soap.security.processor.EncryptProcessor;
import org.nci.soap.security.processor.SignatureProcessor;
import org.nci.soap.security.util.SecurityInfo;
import org.nci.soap.security.util.WSSecurityContext;
import org.nci.xml.security.util.OptionSwitch;
import org.nci.xml.security.util.XmlCipherUtil;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;

public class SoapSecurityBuilder {

	static {
        org.apache.xml.security.Init.init();
    }
	
	static org.apache.commons.logging.Log log = 
	        org.apache.commons.logging.LogFactory.getLog(SoapSecurityBuilder.class.getName());
	
	private SecurityPolicyInfo m_global_policyinfo;
	private Document m_document;
	
	//由调用者指定的处理选项
	private Boolean m_global_isMustUnderstand;
	private String m_global_strActor; 
	
	//中间变量
	private SOAPConstants m_local_soapConstants;
	private Element m_local_securityElem;
	
	//private String m_local_actor;
	
	public SoapSecurityBuilder(SecurityPolicyInfo info) {
		this(info, true, "");
	}
	
	public SoapSecurityBuilder(SecurityPolicyInfo info, String strActor) {	
		this(info, true, strActor);
	}
	
	public SoapSecurityBuilder(SecurityPolicyInfo info, boolean isMustUnderstand, String strActor) {	
		m_global_policyinfo = info;
		
		m_global_isMustUnderstand = isMustUnderstand;
		m_global_strActor = strActor;
		
		m_document = m_global_policyinfo.getDocument();
		m_local_soapConstants = WSSecurityUtil.getSOAPConstants(m_document.getDocumentElement());
	}

	public void setActor(String srcIP, String dstIP){
	
		log.trace("Set Actor Info for SOAP Security");
		m_global_strActor = "From:" + srcIP + " To:" + dstIP;
	}
	
	public Document build() throws WSAccessException {
		
		//Get soap header elem
		log.trace("***HUJQ*** - Begin Build WS Security Soap!");
		
		Element headerElem = null;
		String envelopeURI = m_local_soapConstants.getEnvelopeURI();
		if(envelopeURI == WSConstants.URI_SOAP11_ENV)
			headerElem = WSSecurityUtil.findElement(m_document.getDocumentElement(), WSConstants.ELEM_HEADER, WSConstants.URI_SOAP11_ENV);
		else if(envelopeURI == WSConstants.URI_SOAP12_ENV)
			headerElem = WSSecurityUtil.findElement(m_document.getDocumentElement(), WSConstants.ELEM_HEADER, WSConstants.URI_SOAP12_ENV);
		
		if(headerElem == null){
			log.error("***HUJQ*** - 无法找到SOAP消息头部元素！");
			throw new WSAccessException(WSAccessException.NO_SOAPHEADER + ":" + "无法找到SOAP消息头部元素！");
		}
		
		//Get or create Security Heander if it is not exist
		log.trace("***HUJQ*** - Get or create Security Heander!");
		m_local_securityElem = setSoapSecurityHeader();
		
		//Add Element timestamp
		log.trace("***HUJQ*** - Add Element Timestamp!");
		
		TimestampCreator tsCreator = new TimestampCreator();
		tsCreator.setIsNeedTimetoLife(true);
		tsCreator.setLifeTime(30000);
		
		Element timestampElem = tsCreator.setTimeStampElem(m_document);
		
		//根据时间戳中的创建时间进行用户密钥的计算
		String strUTCCreateTime4UTEK = tsCreator.GetCreateTime();
		m_global_policyinfo.getCipherContextMap().put(WSSecurityContext.MLS_TIMESTAMP, strUTCCreateTime4UTEK);
		
		//Build security env to soap message
		WSSecurityUtil.prependChildElement(m_local_securityElem, timestampElem);
		WSSecurityUtil.prependChildElement(headerElem, m_local_securityElem);
		
		//Signature process
		log.trace("***HUJQ*** - Signature Process!");
		//从策略信息中获得局部加密标签
		List<PartSecurityInfo> list_partSignatureInfo = m_global_policyinfo.getPartSignatureList();
		//按照密级将局部元素进行归类
		List<Integer> list_secretLevel = new ArrayList<Integer>();
		HashMap<Integer, List<PartSecurityInfo>> map_sign = new HashMap<Integer, List<PartSecurityInfo>>();
		
		for(PartSecurityInfo info : list_partSignatureInfo) {
			
			int level = info.SecretLevel;
			
			if(false == map_sign.containsKey(level)){
				list_secretLevel.add(level);
				map_sign.put(level, new ArrayList<PartSecurityInfo>());
			}
			map_sign.get(level).add(info);
		}
		
		//从策略信息中获得全局安全标签
		/**********************************************************************************************************
		 * 对全局签名的处理，
		 * 当局部签名密级中已有全局签名密级时，增加HashMap<Integer(已有密级), List<EncryptPart>(全局结构)>
		 * 当局部签名密级中没有全局签名密级时，增加新密级的HashMap<Integer(全局密级), List<EncryptPart>(全局结构)>
		 **********************************************************************************************************/
		if(0 != m_global_policyinfo.getWholeSecurityInfo().level){
			
			SecurityInfo securityInfo = m_global_policyinfo.getWholeSecurityInfo();
			if(securityInfo.type == 2 || securityInfo.type == 3)
			{
				int wholeLevel = securityInfo.level;
				List<PartSecurityInfo> list_wholeSign = m_global_policyinfo.setWholeSignList(wholeLevel);
				
				if(true == list_secretLevel.contains(wholeLevel)){
		
					for(PartSecurityInfo info : list_wholeSign){
						map_sign.get(wholeLevel).add(info);
					}
				}
				else{
					list_secretLevel.add(wholeLevel);
					map_sign.put(wholeLevel, list_wholeSign);
				}
			}
		}
		
		//do Signature
		for(int refID = 0; refID < list_secretLevel.size(); refID++){
			
			int level = list_secretLevel.get(refID);
			String BSTokenID = "BSTokenRef-" + refID;
			
			log.trace("Signature Process - Build Binary Security Token!" + BSTokenID);
			
			SecurityTokenCreator bstCreator = new SecurityTokenCreator();
			
			byte[] Data;
			if(OptionSwitch.bDEBUG15SOAP)
				Data = new byte[]{Byte.valueOf("11"),Byte.valueOf("22"),Byte.valueOf("33"),Byte.valueOf("44"),Byte.valueOf("55")};
			else {
				Pointer pCertData = new Memory(1024);
				pCertData.clear(1024);
				IntByReference CertDataLen = new IntByReference();
				CertDataLen.setValue(1024);
				int ret = CSP.GetCert(pCertData, CertDataLen);
				if( ret != 0 )
				{
					log.error("获取证书数据失败！");
					return null;
				}
				
				Data = pCertData.getByteArray(0, CertDataLen.getValue());
				
				log.debug("CertData:" + Data.toString());
			}
			
			BinaryDigitalCert cert = new BinaryDigitalCert(BSTokenID, Data);
			bstCreator.setNeedAttribute(true);
			bstCreator.setCinfo(cert);
			Element bstElem = bstCreator.Build(m_document);
			
			m_local_securityElem.appendChild(bstElem);
			
			String strTokenRef = "#" + BSTokenID;
			
			log.trace("Signature Process - do Signature!");
			
			SignatureProcessor signProcessor = new SignatureProcessor();
			Element sigElem = signProcessor.doSignature(m_local_securityElem, map_sign.get(level), level, strTokenRef);
		}
			
		XmlCipherUtil.SaveEncryptedFile(m_document, "./signtemp.xml");
		
		//Encrypt process
		log.trace("***HUJQ*** - Encrypt Process!");
		
		log.trace("Add <xenc:ReferenceList>");
		Element encrefElem = m_document.createElementNS(WSSecurityContext.ENC_NS, "xenc:ReferenceList");
		if(m_document.lookupNamespaceURI(WSSecurityContext.ENC_PREFIX) == null){
			WSSecurityUtil.setNamespace(encrefElem, WSSecurityContext.ENC_NS, WSSecurityContext.ENC_PREFIX);
		}
		
		//从策略信息中获得局部加密标签
		List<PartSecurityInfo> list_partEncryptInfo = m_global_policyinfo.getPartEncryptList();
		
		EncryptProcessor encProcessor = new EncryptProcessor(m_global_policyinfo);
		
		log.trace("Do part Encryption");
		if(list_partEncryptInfo.size() != 0){
			Element encryptedElem = null;
			PartSecurityInfo partEncrypt = null;
			for(int i = 0; i < list_partEncryptInfo.size(); i++){	
				
				log.debug("Encrypt Process - do Encrypt!");
				
				partEncrypt = list_partEncryptInfo.get(i);
				encryptedElem = encProcessor.doEncrypt(partEncrypt);
				partEncrypt.EncryptedNode = (Node)encryptedElem;
			
//				Node adoptNode = m_document.importNode(partEncrypt.EncryptedNode, true);
//				
//				partEncrypt.EncryptingNode.getParentNode().replaceChild(
//							adoptNode, partEncrypt.EncryptingNode);
				
				Element encDataRefElem = m_document.createElementNS(WSSecurityContext.ENC_NS, "xenc:DataReference");
				encDataRefElem.setAttribute("URI", "#" + partEncrypt.EncryptedNodeID);				
				encrefElem.appendChild(encDataRefElem);
			}
		}
		
		log.trace("Do full Encryption");
		if(0 != m_global_policyinfo.getWholeSecurityInfo().level){
			
			SecurityInfo securityInfo = m_global_policyinfo.getWholeSecurityInfo();
			if(securityInfo.type == 1 || securityInfo.type == 3){
				
				log.debug("Encrypt Process - do Encrypt!");
				
				PartSecurityInfo wholeEncrypt = m_global_policyinfo.setWholeEncryptPart(securityInfo.level);
				
				wholeEncrypt.EncryptedNode = (Node)(encProcessor.doEncrypt(wholeEncrypt));
				
				m_document = wholeEncrypt.EncryptedNode.getOwnerDocument();
				
				Element encDataRefElem = m_document.createElementNS(WSSecurityContext.ENC_NS, "xenc:DataReference");
				encDataRefElem.setAttribute("URI", "#" + wholeEncrypt.EncryptedNodeID);				
				encrefElem.appendChild(encDataRefElem);
			}
		}
		
		if(m_global_policyinfo.getPartEncryptList().size() != 0 || m_global_policyinfo.getWholeSecurityInfo().level != 0)
			m_local_securityElem.appendChild(encrefElem);
		
		log.trace("***HUJQ*** - End Build WS Security Soap!");
		
		return m_document;
	}
	
	private Element setSoapSecurityHeader(){
		// String actor = null; 
    	// lookup a security header block that matches actor 
    	Element securityHeader = null;
    		
		try{
			securityHeader = WSSecurityUtil.getSecurityHeader(m_document, m_global_strActor);
        	if ( securityHeader == null )
        	{   
        		// create if nothing found
        		securityHeader = 
        				WSSecurityUtil.findWsseSecurityHeaderBlock
        						(m_document, m_document.getDocumentElement(), m_global_strActor, true);
        		
            	String soapPrefix =
            	WSSecurityUtil.getPrefixNS(m_local_soapConstants.getEnvelopeURI(),
                                     securityHeader);
            	if ( m_global_strActor != null && m_global_strActor.length() > 0 )
            	{
            		// Check for SOAP 1.2 here and use "role" instead of "actor"
            		securityHeader.setAttributeNS(
            								 m_local_soapConstants.getEnvelopeURI(),
                                             soapPrefix
                                             + ":"
                                             + m_local_soapConstants.getRoleAttributeQName().getLocalPart(),
                                             m_global_strActor);
            	}
            	if ( m_global_isMustUnderstand )
            	{
            		securityHeader.setAttributeNS(
            								 m_local_soapConstants.getEnvelopeURI(),
                                             soapPrefix + ":" + WSSecurityContext.ATTR_MUST_UNDERSTAND,
                                             "0");
            	}
        	}	
        }
		catch(WSSecurityException e)
		{
			System.out.println("Exception in SetWSSHeader: " + e.getMessage());
		}
		
		return securityHeader;
	}
}
