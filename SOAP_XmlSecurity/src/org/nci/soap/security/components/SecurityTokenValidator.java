package org.nci.soap.security.components;

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.nci.csp.CSP;
import org.nci.soap.security.util.WSSecurityContext;
import org.nci.xml.security.util.OptionSwitch;
import org.w3c.dom.DOMException;
import org.w3c.dom.Element;

import com.sun.jna.ptr.IntByReference;

public class SecurityTokenValidator {

	static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(SecurityTokenValidator.class.getName());
	
	public int parseBinaryDigitalCert(Element bstElem, BinaryDigitalCert cert){
		
		if(bstElem == null)
			return -1;
		
		cert.strID = bstElem.getAttributeNS(WSSecurityContext.WSU_NS, "Id");
		
		cert.strValueType = bstElem.getAttributeNS(null, "ValueType");
		cert.strEncodingType = bstElem.getAttributeNS(null, "EncodingType");
		
		try {
			cert.byteData = Base64.decode(bstElem.getTextContent());
		} catch (Base64DecodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (DOMException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return 0;
	}
	
	public byte[] getPublicKey(BinaryDigitalCert cert){
		
		if(OptionSwitch.bHASCERT) {
			
			byte[] pCertData = cert.getByteData();
			int CertDataLen = cert.getByteData().length;
			
			byte[] pPubKeyData = new byte[255];
			IntByReference nPubKeyDataLen = new IntByReference();
			nPubKeyDataLen.setValue(255);
			
			int ret = CSP.GetPublicKey(pCertData, CertDataLen, pPubKeyData, nPubKeyDataLen);
			if(ret != 0)
			{
				log.error("***ERROR*** - 获取公钥失败!");
				return null;
			}
			
			int npkdata_len = nPubKeyDataLen.getValue();
			byte[] pubKeyData = new byte[npkdata_len];
			System.arraycopy(pPubKeyData, 0, pubKeyData, 0, npkdata_len);
			
			return pubKeyData;
		}
		else {
			return cert.getByteData();
		}
	}
}
