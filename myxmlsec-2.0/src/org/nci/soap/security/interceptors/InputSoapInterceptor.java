package org.nci.soap.security.interceptors;

import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.log4j.PropertyConfigurator;
import org.nci.csp.CSP;
import org.nci.soap.security.engine.SoapSecurityValidator;
import org.nci.xml.security.util.XmlCipherUtil;
import org.w3c.dom.Document;

public class InputSoapInterceptor implements SOAPHandler<SOAPMessageContext>{

	static org.apache.commons.logging.Log log = 
	        org.apache.commons.logging.LogFactory.getLog(InputSoapInterceptor.class.getName());
	
	public final static String LOG4JCONFIGUREFILE = "/config/log4j.xmlsec.properties";
	public final static String LOG4JPROVIDERCONFIGUREFILE = "/config/log4j.provider.properties";
	
	public String LOCALHOST = "Unknown";
	public String getLocalIP() {
		return LOCALHOST;
	}
	public void setLocalIP(String localIP) {
		this.LOCALHOST = localIP;
	}
	
	public InputSoapInterceptor() {
		System.out.println("***Snail*** - Create InputSoapInterceptor Success!");
	
		String strProjectPath = XmlCipherUtil.getProjectPath();
		String strLog4jConfigurePath = strProjectPath + LOG4JCONFIGUREFILE;
		String strLog4jProviderConfigurePath = strProjectPath + LOG4JPROVIDERCONFIGUREFILE;
		PropertyConfigurator.configure(strLog4jConfigurePath);
		PropertyConfigurator.configure(strLog4jProviderConfigurePath);
		
		//CSP初始化，多次初始化并不会有任何不良影响
		byte[] bApp = "XML-SOAP ENCRYPTION".getBytes();
		CSP.SetOperateDevice(bApp);
	}
	
	@Override
	public void close(MessageContext arg0) {
		// TODO Auto-generated method stub
	}

	@Override
	public boolean handleFault(SOAPMessageContext arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean handleMessage(SOAPMessageContext ctx) {
		// TODO Auto-generated method stub
		
		//不予许Base64自动换行
		System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");
		
		//入站消息为false，不进行拦截
		Boolean outbound = (Boolean)ctx.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if(outbound) {
			return true;		
		}
		
		log.trace("***HUJQ*** - 消息拦截成功-入站");
		
		//获得SOAP消息文档
		SOAPMessage soapMessage = ctx.getMessage();
		Document doc = null;
		try{
			doc = soapMessage.getSOAPPart().getEnvelope().getOwnerDocument();
		}catch(SOAPException e){
			return false;
		}
		
		String strProjectPath = XmlCipherUtil.getProjectPath();
		String strInputSoapFilePath = strProjectPath + "/temp/XmlsecInputSoap.xml";
		XmlCipherUtil.SaveEncryptedFile(doc, strInputSoapFilePath);
		
		SoapSecurityValidator validator = new SoapSecurityValidator(doc, LOCALHOST);
		
		log.trace("***HUJQ*** - 进行SOAP消息解析处理!");
		doc = validator.validate();
		if(doc == null){	
			log.error("***HUJQ*** - SOAP消息解析错误!");
			return false;
		}
		
		String strResultSoapFilePath = strProjectPath + "/temp/DeResultSoap.xml";
		XmlCipherUtil.SaveEncryptedFile(doc, strResultSoapFilePath);
		
		try {
			soapMessage.saveChanges();
		} catch (SOAPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		log.trace("***HUJQ*** - 消息安全封装处理成功");
		
		return true;
	}

	@Override
	public Set<QName> getHeaders() {
		// TODO Auto-generated method stub
		return null;
	}
}
