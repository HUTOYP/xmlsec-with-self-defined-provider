package org.nci.soap.security.processor;

import java.util.List;

import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.XMLCipher;
import org.nci.soap.security.util.WSSecurityContext;
import org.nci.xml.security.key.Key_v810;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

public class DecryptProcessor {

	static org.apache.commons.logging.Log log = 
	        org.apache.commons.logging.LogFactory.getLog(DecryptProcessor.class.getName());
	
	String m_CurrentTimestamp;
	public DecryptProcessor(String currentTimestamp) {
		
		m_CurrentTimestamp = currentTimestamp;
	}
	
	public Element doDecrypt(Element decryptingElem){
		
		return DecryptProcess(decryptingElem);
	}
	
	public Element DecryptProcess(Element encryptingElem){
		
		Document context = encryptingElem.getOwnerDocument();

		//解密时需要的密级等信息，如果没有密级信息，则到EncryptionProperty中获得密级信息
		Key_v810 key = new Key_v810();
						
		//解密处理后的XML文档对象
   		Document resultDoc = null;
   		
		try {
			log.debug("invoke XMLCipher.getInstance");
			XMLCipher xmlCipher = XMLCipher.getInstance();

			//get secret level and device id from element EncryptionProperty
			log.debug("get secret level and device id from element EncryptionProperty");
				
//			NodeList encryptionPropertyList =
//					encryptingElem.getElementsByTagNameNS(WSSecurityContext.SOAP800_PREFIX,WSSecurityContext.CP_LN);
	        
			List<Element> encryptionPropertyList = WSSecurityUtil.findElements(encryptingElem, WSSecurityContext.CP_LN, WSSecurityContext.SOAP800_NS);
			for(int i = 0; i < encryptionPropertyList.size(); i++) {
	            Node n = encryptionPropertyList.get(i);
	            if (null != n && n.hasAttributes()) {
	            	
	            	NamedNodeMap nnm = n.getAttributes();
	            		
//	            	String secLevel = nnm.getNamedItem("SecLevel").getNodeValue();
//	            	if(secLevel.equals(WSSecurityContext.SECLEVEL_TOP))
//	            		key.setSecretLevel(1);
//	            	else if(secLevel.equals(WSSecurityContext.SECLEVEL_CONFIDENTIAL))
//	            		key.setSecretLevel(2);
//	            	else if(secLevel.equals(WSSecurityContext.SECLEVEL_SECRET))
//	            		key.setSecretLevel(3);
	    
	            	key.setIV(nnm.getNamedItem(WSSecurityContext.MLS_IV).getNodeValue());
	            	key.setAlgID(nnm.getNamedItem(WSSecurityContext.MLS_ALGID).getNodeValue());
	            	key.setSrcDevice(nnm.getNamedItem(WSSecurityContext.MLS_MMJID_SRC).getNodeValue());
	            	key.setDstDevice(nnm.getNamedItem(WSSecurityContext.MLS_MMJID_DST).getNodeValue());
	            	
	            	key.SetTimeStamp(m_CurrentTimestamp);
	            }
	        }
			
			//xmlCipher.init
			log.debug("invoke xmlCipher.init");
   			xmlCipher.init(XMLCipher.DECRYPT_MODE, key);			
			
   			//xmlCipher.doFianl
   			log.debug("invoke xmlCipher.doFianl");
   			resultDoc =  xmlCipher.doFinal(context, encryptingElem);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
   		
	    return resultDoc.getDocumentElement();	
	}
}
