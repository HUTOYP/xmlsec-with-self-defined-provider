package org.nci.soap.security.processor;

import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.EncryptionProperties;
import org.apache.xml.security.encryption.EncryptionProperty;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.utils.Base64;
import org.nci.csp.CSP;
import org.nci.soap.policy.SecurityPolicyInfo;
import org.nci.soap.policy.analysis.PartSecurityInfo;
import org.nci.soap.security.util.EncryptProcessContext;
import org.nci.soap.security.util.IProcessContext;
import org.nci.soap.security.util.WSSecurityContext;
import org.nci.xml.security.key.Key_v810;
import org.nci.xml.security.util.OptionSwitch;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class EncryptProcessor {

	static org.apache.commons.logging.Log log = 
	        org.apache.commons.logging.LogFactory.getLog(EncryptProcessor.class.getName());
	
	SecurityPolicyInfo m_global_policyinfo;
	
	public EncryptProcessor(SecurityPolicyInfo policyinfo){
		
		m_global_policyinfo = policyinfo;
	}
	
	public Element doEncrypt(PartSecurityInfo part){
		
		Element encryptingElem = (Element)part.EncryptingNode;
		
		IProcessContext encContext = new EncryptProcessContext(part.ContentFlag, part.EncryptedNodeID, part.SecretLevel);
		
		return EncryptProcess(encryptingElem, encContext, m_global_policyinfo);
	}
	
	public Element EncryptProcess(Element encryptingElem, IProcessContext encContext, SecurityPolicyInfo policyinfo){
		
		String EncryptAlgorithm = WSSecurityContext.ALG_ENCR_LEVEL_NORMAL;
		
		int nLevel = encContext.getProcessLevel();
		
		//HUJQ-加密算法理论上是固定的，暂时注释密级选择部分
//		switch(nLevel){
//			case 1:
//				EncryptAlgorithm = WSSecurityContext.ALG_ENCR_LEVEL_TOP; break;
//			case 2:
//				EncryptAlgorithm = WSSecurityContext.ALG_ENCR_LEVEL_NORMAL; break;
//			case 3:
//				EncryptAlgorithm = WSSecurityContext.ALG_ENCR_LEVEL_NORMAL; break;
//		}
		
		log.debug("new Key_v810 and init");
		
		Key_v810 symmetricKey = new Key_v810();
		
		String realIV = "";
		if(OptionSwitch.bDEBUG15SOAP) {
			realIV = "6i22Q3/36K6l7PlJvp/3Iw==";
		} else {
			//每次加密更换IV
			byte[] pRandom = new byte[16];
			int ret = CSP.GenRandom(16, pRandom);
			if(ret != 0)
				log.error("***HUJQ*** - 获取随机数作为IV失败！");
			
			realIV = Base64.encode(pRandom);
			
//			realIV = "AQEBAQEBAQEBAQEBAQEBAQ==";
		}
		
		symmetricKey.setIV(realIV);
		symmetricKey.setAlgID(policyinfo.getCipherContextMap().get(WSSecurityContext.MLS_ALGID));
		symmetricKey.setSrcDevice(policyinfo.getCipherContextMap().get(WSSecurityContext.MLS_MMJID_SRC));
		symmetricKey.setDstDevice(policyinfo.getCipherContextMap().get(WSSecurityContext.MLS_MMJID_DST));
		symmetricKey.SetTimeStamp(policyinfo.getCipherContextMap().get(WSSecurityContext.MLS_TIMESTAMP));
		
		Document doc = encryptingElem.getOwnerDocument();
		Document resultDoc = null;
		
		try {
			
			//构造XMLCipher对象，指定加密算法
			log.debug("invoke XMLCipher.getInstance");
			XMLCipher xmlCipher = XMLCipher.getInstance(EncryptAlgorithm);
		
			//初始化XMLCipher对象，指定加密方式及密钥信息
			log.debug("invoke xmlCipher.init");
			xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);
			
			//增加加密算法元素
			xmlCipher.createEncryptionMethod(EncryptAlgorithm);

			//增加加密属性元素
			log.debug("Add EncryptionProperties");
		    Element cipherPropertyElem = doc.createElementNS(WSSecurityContext.SOAP800_NS, WSSecurityContext.SOAP800_PREFIX + ":" + WSSecurityContext.CP_LN);
			WSSecurityUtil.setNamespace(cipherPropertyElem, WSSecurityContext.SOAP800_NS, WSSecurityContext.SOAP800_PREFIX);
			
			cipherPropertyElem.setAttribute(WSSecurityContext.MLS_IV, realIV);
			cipherPropertyElem.setAttribute(WSSecurityContext.MLS_ALGID, policyinfo.getCipherContextMap().get(WSSecurityContext.MLS_ALGID));
			cipherPropertyElem.setAttribute(WSSecurityContext.MLS_MMJID_SRC, policyinfo.getCipherContextMap().get(WSSecurityContext.MLS_MMJID_SRC));
			cipherPropertyElem.setAttribute(WSSecurityContext.MLS_MMJID_DST, policyinfo.getCipherContextMap().get(WSSecurityContext.MLS_MMJID_DST));

//			if(nLevel == 1){
//				cipherPropertyElem.setAttribute("SecLevel", WSSecurityContext.SECLEVEL_TOP);
//			}
//			else if(nLevel == 2){
//				cipherPropertyElem.setAttribute("SecLevel", WSSecurityContext.SECLEVEL_CONFIDENTIAL);
//			}
//			else if(nLevel == 3){
//				cipherPropertyElem.setAttribute("SecLevel", WSSecurityContext.SECLEVEL_SECRET);
//			}
//			else{
//				cipherPropertyElem.setAttribute("SecLevel", "unknow");
//			}
		    
			EncryptionProperty property = xmlCipher.createEncryptionProperty();
			property.addEncryptionInformation(cipherPropertyElem);
			
			EncryptionProperties properties = xmlCipher.createEncryptionProperties();
			properties.addEncryptionProperty(property);
			
			xmlCipher.getEncryptedData().setEncryptionProperties(properties);
			
			//进行加密处理
			String id;
			if(encContext instanceof EncryptProcessContext){	
				id = ((EncryptProcessContext) encContext).getEncryptedID();
				xmlCipher.getEncryptedData().setId(id);
				
				log.debug("invoke xmlCipher.doFinal");
				resultDoc = xmlCipher.doFinal(doc, encryptingElem, ((EncryptProcessContext) encContext).getContentFlag());
			}      
		
			return resultDoc.getDocumentElement();
		
		} catch (XMLEncryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
}
