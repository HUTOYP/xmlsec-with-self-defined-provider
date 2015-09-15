package org.nci.xml.security.util;

import org.w3c.dom.Document;

/**
 * 签名处理上下文，用以将应用层签名信息向下传递
 * @author hujq
 *
 */
public class SignatureContext {
	
	private static SignatureContext m_instance = null;
	private SignatureContext(){}
	
	public static SignatureContext GetInstance(){
		if(m_instance == null)
			m_instance = new SignatureContext();
		
		return m_instance;
	}
	
	int m_signType;
	
	public void SetSignatureType(int type){
		m_signType = type;
	}
	
	public int GetSignatureType(){
		return m_signType;
	}
	
	Document m_document;
	
	public void SetDocument(Document doc){
		m_document = doc;
	}
	
	public Document GetDocument(){
		return m_document;
	}
	
}
