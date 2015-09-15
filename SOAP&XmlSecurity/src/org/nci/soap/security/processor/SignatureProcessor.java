package org.nci.soap.security.processor;

import java.util.ArrayList;
import java.util.List;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.doomdark.uuid.UUIDGenerator;
import org.nci.soap.policy.analysis.PartSecurityInfo;
import org.nci.soap.security.util.IProcessContext;
import org.nci.soap.security.util.SignatureProcessContext;
import org.nci.soap.security.util.WSSecurityContext;
import org.nci.xml.security.key.PublicKey_v810;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SignatureProcessor {
	
	static org.apache.commons.logging.Log log = 
	        org.apache.commons.logging.LogFactory.getLog(SignatureProcessor.class.getName());
	
	public Element doSignature(Element headerElem, List<PartSecurityInfo> signPart, int level, String strURL) {
		
		UUIDGenerator m_uuidGenerator = UUIDGenerator.getInstance();
		org.doomdark.uuid.UUID uuid = m_uuidGenerator.generateRandomBasedUUID();
		
		List<Element> elements = new ArrayList<Element>();
		for(int i = 0; i < signPart.size(); i++)
			elements.add((Element) signPart.get(i).EncryptingNode);
		
		IProcessContext signContext = new SignatureProcessContext(uuid.toString(), strURL, level);
		
		return SignatureProcess(headerElem, elements, signContext);
	}
	
	public Element SignatureProcess(Element headerElem, List<Element> signPart, IProcessContext signContext){
				
		PublicKey_v810 pk = new PublicKey_v810();
		
		int nLevel = signContext.getProcessLevel();
		
		String SignatureAlgorithm = WSSecurityContext.ALG_SIGN_LEVEL_NORMAL; 
		
		//HUJQ-签名算法理论上是固定的，暂时注释密级选择部分
//		switch(nLevel){
//			case 1:
//				SignatureAlgorithm = WSSecurityContext.ALG_SIGN_LEVEL_TOP; break;
//			case 2:
//				SignatureAlgorithm = WSSecurityContext.ALG_SIGN_LEVEL_NORMAL; break;
//			case 3:
//				SignatureAlgorithm = WSSecurityContext.ALG_SIGN_LEVEL_NORMAL; break;
//		}

		try
		{
			Document doc = headerElem.getOwnerDocument();
			
			log.debug("new XMLSignature");
			XMLSignature sign = new XMLSignature(doc, null, SignatureAlgorithm);
     	   
			String uri = "";
			String id = "";
			if(signContext instanceof SignatureProcessContext){
				
				uri = ((SignatureProcessContext) signContext).getSignatureBSTID();
				id = ((SignatureProcessContext) signContext).getSignatureID();
				
				if(id != null && id != "")
					sign.setId(id);
			}

			log.debug("add transform");
			for(int i = 0; i < signPart.size(); i++)
			{
				//create the transforms object for the Document/Reference
				Transforms transforms = new Transforms(doc);
				
				//WSSecurity规范中一般不要求TRANSFORM_ENVELOPED_SIGNATURE标志
				//transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
				transforms.addTransform(Transforms.TRANSFORM_C14N11_WITH_COMMENTS);
		         
				if(signPart.get(i).hasAttribute("wsu:Id")){
					sign.addDocument("#"+signPart.get(i).getAttribute("wsu:Id"), transforms, WSSecurityContext.ALG_DIGEST_810);
				}
				else if(signPart.get(i).hasAttribute("Id")){
					sign.addDocument("#"+signPart.get(i).getAttribute("Id"), transforms, WSSecurityContext.ALG_DIGEST_810);
				}
				else if(signPart.get(i).hasAttribute("ID")){
					sign.addDocument("#"+signPart.get(i).getAttribute("ID"), transforms, WSSecurityContext.ALG_DIGEST_810);
				}
			}
	        
			Element _elem = sign.getElement();
			
			if(headerElem != null){	
				headerElem.appendChild(_elem);
			}
			
			log.debug("invoke sign.sign");
	        sign.sign(null);
	        
	        //add element <keyinfo>
	        log.debug("add element <keyinfo>");
			if(uri != null && uri != "")
				addKeyInfo(doc, _elem, uri);
	        
		    return sign.getElement();    
		}
		catch(Exception e){
			System.out.println(e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
	
	public void addKeyInfo(Document doc, Element ele, String uri)
    {
    	Element KeyInfoElem = doc.createElementNS(WSSecurityContext.SIG_NS, WSSecurityContext.SIG_PREFIX + ":KeyInfo");
    	Element STReferenceElem = doc.createElementNS(WSSecurityContext.WSSE_NS, WSSecurityContext.WSSE_PREFIX + ":SecurityTokenReference");
    	Element ReferenceElem = doc.createElementNS(WSSecurityContext.WSSE_NS,WSSecurityContext.WSSE_PREFIX + ":Reference");
    	ReferenceElem.setAttribute("URI", uri);
    	
    	STReferenceElem.appendChild(ReferenceElem);
    	KeyInfoElem.appendChild(STReferenceElem);
    	
    	ele.appendChild(KeyInfoElem);
    }
}
