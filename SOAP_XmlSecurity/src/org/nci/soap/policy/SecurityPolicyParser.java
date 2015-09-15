package org.nci.soap.policy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.WSSecurityUtil;
import org.nci.soap.policy.analysis.PartSecurityInfo;
import org.nci.soap.policy.analysis.SecurityPolicyAnalyzer;
import org.nci.soap.security.util.LocalMMJIDConfig;
import org.nci.soap.security.util.ProxyStruct;
import org.nci.soap.security.util.SecurityInfo;
import org.nci.soap.security.util.WSSecurityContext;
import org.nci.xml.security.util.OptionSwitch;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SecurityPolicyParser {

	static org.apache.commons.logging.Log log = 
	        org.apache.commons.logging.LogFactory.getLog(SecurityPolicyParser.class.getName());
	
	private Document m_document;
	private ProxyStruct m_struct;
	SecurityPolicyInfo m_securityPolicyInfo;
	public SecurityPolicyParser(Document doc, ProxyStruct struct) {
		
		m_document = doc;
		m_struct = struct;
		
		m_securityPolicyInfo = new SecurityPolicyInfo();
	}
	
	public int parse() {
			
		log.trace("Starting Parse Plain SOAP!");
		SecurityPolicyAnalyzer analyzer = new SecurityPolicyAnalyzer(m_document);
		
		boolean ret = true;
		
		try{
			log.trace("Get SOAP Envelope!");
			Element EnvelopeElem = analyzer.getEnvelope();
			if(EnvelopeElem == null){
				log.error("Method 'analyzer.getEnvelope' ERROR!");
				return -1;
			}
			
			log.trace("Get Security Policy Header!");
			Element securityHeaderElem = null;
			securityHeaderElem = analyzer.getSecurityHeader(null);
			if(securityHeaderElem == null){
				log.error("Method 'getSecurityHeader' ERROR!");
				return -1;
			}
			
			log.trace("Get SecurityContextToken!");
			Element securityContextTokenElem = analyzer.getSecurityContextToken(securityHeaderElem);

			Map<String, String> contextMap = new HashMap<String, String>();
			ret = analyzer.getSecurityContextTokenInfo(securityContextTokenElem, contextMap);
			if(ret == false){
				log.error("Method 'getSecurityContextTokenInfo' ERROR!");
				return -1;
			}
			
			log.trace("Analyze Encrypt and Sign Policy...");
			SecurityInfo info = analyzer.judgeFullSecurityLevel(securityContextTokenElem, WSSecurityContext.MSL_LN, WSSecurityContext.MLS_NS);
			log.trace("Full Security type ==> " + info.type);
			log.trace("Full Security Level ==> " + info.level);
			
			Element bodyElem = WSSecurityUtil.findBodyElement(m_document);
			
			log.trace("Get Argument Encrypted Part!");
			List<PartSecurityInfo> encPartList = new ArrayList<PartSecurityInfo>();
			ret = analyzer.getSecurityPart(bodyElem, WSSecurityContext.ASL_LN, WSSecurityContext.MLS_NS, WSSecurityContext.FLAG_ENC, encPartList);
			if(ret == false)	
				log.warn("Argument Encrypted Part is Empty!");
			
			log.trace("Get Argument Signature Part!");
			List<PartSecurityInfo> signPartList = new ArrayList<PartSecurityInfo>();
			ret = analyzer.getSecurityPart(bodyElem, WSSecurityContext.ASL_LN, WSSecurityContext.MLS_NS, WSSecurityContext.FLAG_SIGN, signPartList);
			if(ret == false)	
				log.warn("Argument Signature Part is Empty!");
			
			//test
//			contextMap.put(WSSecurityContext.MLS_IV, "6i22Q3/36K6l7PlJvp/3Iw==");
			
			contextMap.put(WSSecurityContext.MLS_ALGID, WSSecurityContext.ALG_ENCR_LEVEL_NORMAL);
			if(!OptionSwitch.bDEBUG15SOAP)
				contextMap.put(WSSecurityContext.MLS_MMJID_SRC, LocalMMJIDConfig.GetInstance().GetLocalMMJID());
			else
				contextMap.put(WSSecurityContext.MLS_MMJID_SRC, "11-22-33-44");
			
			contextMap.put(WSSecurityContext.MLS_MMJID_DST, m_struct.MMJID);
			
			m_securityPolicyInfo.setSoapDocument(m_document);
			m_securityPolicyInfo.setSecurityHeaderElem(securityHeaderElem);
			m_securityPolicyInfo.setSecurityContextTokenElem(securityContextTokenElem);
			m_securityPolicyInfo.setCipherContextMap(contextMap);
			m_securityPolicyInfo.setWholeSecurityInfo(info);
			
			m_securityPolicyInfo.setPartEncryptList(encPartList);
			m_securityPolicyInfo.setPartSignatureList(signPartList);
			
			log.trace("Finished Parse Plain SOAP!");
			
		}catch(WSSecurityException wse)
		{
			log.error("build: WSSecurityException" + wse.getMessage());
			return -1;
		}
		return 0;
	}
	
	public SecurityPolicyInfo getSecurityPolicyInfo() {
		return m_securityPolicyInfo;
	}
}
