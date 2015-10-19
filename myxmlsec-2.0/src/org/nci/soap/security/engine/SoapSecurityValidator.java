package org.nci.soap.security.engine;

import java.util.ArrayList;
import java.util.List;

import org.apache.ws.security.util.WSSecurityUtil;
import org.nci.soap.security.components.BinaryDigitalCert;
import org.nci.soap.security.components.SecurityTokenValidator;
import org.nci.soap.security.components.TimestampValidator;
import org.nci.soap.security.exception.WSAccessException;
import org.nci.soap.security.processor.DecryptProcessor;
import org.nci.soap.security.processor.ValidateProcessor;
import org.nci.soap.security.util.WSSecurityContext;
import org.nci.xml.security.util.XmlCipherUtil;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class SoapSecurityValidator {
	
	static {
        org.apache.xml.security.Init.init();
    }
	
	static org.apache.commons.logging.Log log = 
	        org.apache.commons.logging.LogFactory.getLog(SoapSecurityValidator.class.getName());
	
	Document m_document;
	
	String m_localIP;
	
	public SoapSecurityValidator(Document doc, String ip) {
		
		m_document = doc;
		
		m_localIP = ip;
	}
	
	public Document validate() {
		
		log.trace("***HUJQ*** - Starting Verify Security SOAP!");
	
		boolean SOAPTYPE_VERSION_11 = true;
		Element headerElem = WSSecurityUtil.findElement(m_document, WSSecurityContext.ELEM_HEADER, WSSecurityContext.URI_SOAP11_ENV);
		if(headerElem == null){
			
			SOAPTYPE_VERSION_11 = false;
			headerElem = WSSecurityUtil.findElement(m_document, WSSecurityContext.ELEM_HEADER, WSSecurityContext.URI_SOAP12_ENV);
			if(headerElem == null){
				log.error("***HUJQ*** - can not find element 'head'");
				return null;
			}
		}
		
		//find Actor and get Element 'Security'
		log.trace("***HUJQ*** - find Actor and get Element <Security>");
		
		Element securityHeaderElem = checkAndFindSecurityHeader(headerElem, SOAPTYPE_VERSION_11);
		if(securityHeaderElem == null){
			log.error("***HUJQ*** - can not find element 'Security'");
			return null;
		}
		
		//verify Timestamp
		log.trace("***HUJQ*** - Verify Timestamp");
		
		Element tsElem = WSSecurityUtil.findElement(securityHeaderElem, WSSecurityContext.TIMESTAMP_TOKEN_LN, WSSecurityContext.WSU_NS);
		
		String strUTCCreateTime4UTEK = "";
		
		try {
			TimestampValidator tsv = new TimestampValidator();
			boolean rst = tsv.validate(tsElem);
			
			//根据时间戳中的创建时间进行用户密钥的计算
			strUTCCreateTime4UTEK = tsv.GetCreateTime();
			
			if(rst == true){
				log.debug("Timestamp Validate Success!");
				System.out.println("Timestamp Validate Success!");
			}
			else{
				log.error("Timestamp Validate Error!");
				System.out.println("Timestamp Validate Error!");
			}
		} catch (WSAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//decrypt process
		log.trace("***HUJQ*** - Starting Decryption Process...!");
		
		Element bodyElem = WSSecurityUtil.findBodyElement(m_document);
		
		log.trace("Find Element <ReferenceList>");
		Element referenceListElem = WSSecurityUtil.findElement(securityHeaderElem, WSSecurityContext.REF_LIST_LN, WSSecurityContext.ENC_NS);
		List<Element> referenceElemList = WSSecurityUtil.findElements(referenceListElem, WSSecurityContext.ENC_DATAREF_LN, WSSecurityContext.ENC_NS);
		if(referenceElemList == null){
			log.trace("can not find encryption reference!");
			System.out.println("DataReference is NULL!");
		}
		else{
			log.trace("Decryption Process Count ==> " + referenceElemList.size());
			
			DecryptProcessor decryptProcessor = new DecryptProcessor(strUTCCreateTime4UTEK);
			
			for(int i = referenceElemList.size() - 1; i >= 0; i--)
			{
				String uri = referenceElemList.get(i).getAttribute("URI");
				System.out.println("Current Decryption Process URI ==> " + uri);
				String id = uri.substring(1);
				Element decryptingElem = WSSecurityUtil.findElementById(bodyElem, id, true);
				
				Element PlainElem = decryptProcessor.doDecrypt(decryptingElem);
				Node adoptNode = m_document.importNode(PlainElem, true);
	
				m_document = PlainElem.getOwnerDocument();
			}
		}
		
		if(referenceListElem != null)
			securityHeaderElem.removeChild(referenceListElem);
		
		log.trace("***HUJQ*** - Decryption Process Success!");
		
		XmlCipherUtil.SaveEncryptedFile(m_document, "C:/temp.xml");

		//validate process
		log.trace("***HUJQ*** - Starting SignValidate Process...!");
		
		List<Element> signatureElemList = WSSecurityUtil.findElements(securityHeaderElem, WSSecurityContext.SIG_LN, WSSecurityContext.SIG_NS);
		//记录所有做过签名的元素，用于在验证完成后删除元素中的SIG-ID属性
		List<Element> totalSignElem = new ArrayList<Element>();
		
		ValidateProcessor validateProcessor = new ValidateProcessor();
		SecurityTokenValidator tokenValidator = new SecurityTokenValidator();
		
		for(int i = 0; i < signatureElemList.size(); i++){
			Element currentSignatureElem = signatureElemList.get(i);
			
			//find binary security token reference
			Element STRefElem = WSSecurityUtil.findElement(currentSignatureElem, "SecurityTokenReference", WSSecurityContext.WSSE_NS);
			Element BSTRefElem = WSSecurityUtil.findElement(STRefElem, "Reference", WSSecurityContext.WSSE_NS);
			String strURI = BSTRefElem.getAttribute("URI");
			String strID = strURI.substring(1);
			
			//find binary security token
			Element BSTElem = WSSecurityUtil.findElementById(securityHeaderElem, strID, false);
			
			//parse cert information from binary security token
			BinaryDigitalCert cert = new BinaryDigitalCert();
			tokenValidator.parseBinaryDigitalCert(BSTElem, cert);
			
			List<Element> signPartList = new ArrayList<Element>();
			NodeList RefList = currentSignatureElem.getElementsByTagNameNS(WSSecurityContext.SIG_NS, "Reference");
			for(int j = 0; j < RefList.getLength(); j++){
				Element RefElem = (Element)RefList.item(j);
				String strRefURI = RefElem.getAttribute("URI");
				String strRefID = strRefURI.substring(1);
				
				Element signPartElem = WSSecurityUtil.findElementById(m_document.getDocumentElement(), strRefID, false);
				signPartList.add(signPartElem);
			}
			
			if(false == validateProcessor.doValidate(signPartList, currentSignatureElem, cert)){
				log.error("***HUJQ*** - Signature Validate Failure!");
				System.out.println("Signature Validate Failure!");
				return null;
			}
			else{
				securityHeaderElem.removeChild(currentSignatureElem);
				securityHeaderElem.removeChild(BSTElem);
				
				log.trace("Signature Validate Success!");
				System.out.println("Signature Validate Success!");
				
				for(int k = 0; k < signPartList.size(); k++){
					totalSignElem.add(signPartList.get(k));
				}
			}
		}
		
		for(int i = 0; i < totalSignElem.size(); i++)
			totalSignElem.get(i).removeAttribute("wsu:Id");
		
		log.trace("***HUJQ*** - SignValidate Process Success!");
		
		headerElem.removeChild(securityHeaderElem);
		log.trace("***HUJQ*** - Finished Verify Security SOAP!");
		
		return m_document;
	}
	
	public Element checkAndFindSecurityHeader(Element header, boolean soap11){
		
		Element securityHeaderElem = null;
		
		List<Element> tempElemList = WSSecurityUtil.findElements(header, WSSecurityContext.WSSE_LN, WSSecurityContext.WSSE_NS);
		
		if(tempElemList.size() == 1){
			securityHeaderElem = tempElemList.get(0);
			return securityHeaderElem;
		}
		
		String strActor;
		for(int i = 0; i < tempElemList.size(); i++){
			
			Element currentSecurityHeaderElem = tempElemList.get(i);
			
			String strActorWithNS = currentSecurityHeaderElem.getAttribute(WSSecurityContext.ATTR_ACTOR);
			
			boolean hasActor = currentSecurityHeaderElem.hasAttribute("soap:" + WSSecurityContext.ATTR_ACTOR);
			if(!hasActor)
				continue;
			
			if(soap11 == true)
				strActor = currentSecurityHeaderElem.getAttributeNS(WSSecurityContext.URI_SOAP11_ENV, WSSecurityContext.ATTR_ACTOR);
			else
				strActor = currentSecurityHeaderElem.getAttributeNS(WSSecurityContext.URI_SOAP12_ENV, WSSecurityContext.ATTR_ACTOR);
			
			if(strActor != null && strActor != ""){
				int index = strActor.indexOf("To:");
				String dstIP = strActor.substring(index + 3);
				
				if(!dstIP.equals(m_localIP)){
					return null;
				}
				else
					securityHeaderElem = currentSecurityHeaderElem;
			}
			else if(strActorWithNS != null && strActorWithNS != ""){
				int index = strActorWithNS.indexOf("To:");
				String dstIP = strActorWithNS.substring(index + 3);
				
				if(!dstIP.equals(m_localIP)){
					return null;
				}
				else
					securityHeaderElem = currentSecurityHeaderElem;
			}
			else
				//调试用，正常情况下不允许Actor属性为空
				securityHeaderElem = currentSecurityHeaderElem;
		}
		return securityHeaderElem;
	}
}
