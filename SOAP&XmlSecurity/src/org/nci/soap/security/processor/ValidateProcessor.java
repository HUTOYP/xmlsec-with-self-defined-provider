package org.nci.soap.security.processor;

import java.io.File;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.signature.XMLSignature;
import org.nci.soap.security.components.BinaryDigitalCert;
import org.nci.soap.security.components.SecurityTokenValidator;
import org.nci.soap.security.util.WSSecurityContext;
import org.nci.xml.security.key.PublicKey_v810;
import org.nci.xml.security.util.SignatureContext;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class ValidateProcessor {

	static org.apache.commons.logging.Log log = 
	        org.apache.commons.logging.LogFactory.getLog(ValidateProcessor.class.getName());
	
	public boolean doValidate(List<Element> elements, Element signatureElem, BinaryDigitalCert cert){
		
		int level = 0;
		Element signMethodElem = WSSecurityUtil.findElement(signatureElem, "SignatureMethod", WSSecurityContext.SIG_NS);
		String signMethod = signMethodElem.getAttribute("Algorithm");
		
		if(signMethod.equals(WSSecurityContext.ALG_SIGN_LEVEL_TOP))
			level = 1;
		else if(signMethod.equals(WSSecurityContext.ALG_SIGN_LEVEL_NORMAL))
			level = 2;

		int rst = ValidateProcess(elements, signatureElem, cert, level);
		
		if(rst == WSSecurityContext.RST_VERIFYRESULT_VALID)
			return true;
		else
			return false;
	}
	
	public int ValidateProcess(List<Element> elements, Element signatureElem, BinaryDigitalCert cert, int level){
		
		//get public key from cert
		SecurityTokenValidator validator = new SecurityTokenValidator();

		byte[] pkdata = validator.getPublicKey(cert);
		
		PublicKey_v810 pk = new PublicKey_v810(pkdata);
		
		try {
			log.debug("construct temp document");
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
     	    dbf.setNamespaceAware(true);
     	    
     	    DocumentBuilder db = dbf.newDocumentBuilder();
     	    Document tempdoc = db.newDocument();
     	    tempdoc = (Document) signatureElem.getOwnerDocument().cloneNode(true);
     	    Element root = tempdoc.getDocumentElement();
     	    
			Node adoptNode = tempdoc.importNode(signatureElem, true);
            root.appendChild(adoptNode);
            
            //for what?
            SignatureContext.GetInstance().SetDocument(tempdoc);
            
			File signatureFile = new File("tmpfile.xml");
			String baseURI = signatureFile.toURL().toString();
			
			//do validate
			log.debug("new XMLSignature");
			XMLSignature sig = new XMLSignature(signatureElem, baseURI);
			if (cert != null) {
				
				log.debug("invoke sig.checkSignatureValue");
				boolean check = sig.checkSignatureValue(pk);	
				if (check)
					return WSSecurityContext.RST_VERIFYRESULT_VALID;
				else
					return WSSecurityContext.RST_VERIFYRESULT_INVALID;
			} 
			else {	
				System.out.println("Did not find a Certificate");
				return WSSecurityContext.RST_VERIFYRESULT_NOCERT;
			}
		}
		catch (Exception e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
			
			return WSSecurityContext.RST_VERIFYRESULT_EXCEPTION;
		}
	}
}
