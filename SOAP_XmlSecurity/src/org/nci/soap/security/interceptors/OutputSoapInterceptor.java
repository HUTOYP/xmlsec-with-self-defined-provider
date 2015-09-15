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
import org.nci.soap.policy.SecurityPolicyInfo;
import org.nci.soap.policy.SecurityPolicyParser;
import org.nci.soap.security.engine.SoapSecurityBuilder;
import org.nci.soap.security.exception.WSAccessException;
import org.nci.soap.security.util.ProxyConfig;
import org.nci.soap.security.util.ProxyStruct;
import org.nci.xml.security.util.XmlCipherUtil;
import org.w3c.dom.Document;

public class OutputSoapInterceptor implements SOAPHandler<SOAPMessageContext>{

	static org.apache.commons.logging.Log log = 
	        org.apache.commons.logging.LogFactory.getLog(OutputSoapInterceptor.class.getName());
	
	public final static String CONFIGUREFILE = "/config/ProxyConfig.xml";
	public final static String LOG4JCONFIGUREFILE = "/config/log4j.xmlsec.properties";
	public final static String LOG4JPROVIDERCONFIGUREFILE = "/config/log4j.provider.properties";
	
	//本端IP注入
	public String LOCALHOST = "unknown";
	public String getLocalIP() {
		return LOCALHOST;
	}
	public void setLocalIP(String localIP) {
		this.LOCALHOST = localIP;
	}
	
	//对端IP注入
	public String DESTHOST = "unknown";
	public String getDestIP() {
		return DESTHOST;
	}
	public void setDestIP(String destIP) {
		this.DESTHOST = destIP;
	}
	
	//对端PORT注入
	public String DESTPORT = "unknown";
	public String getDestPort() {
		return DESTPORT;
	}
	public void setDestPort(String destPort) {
		this.DESTPORT = destPort;
	}
	
	//互通标志注入
	public int FLAG_WG = 1;
	public int getFlag() {
		return FLAG_WG;
	}
	public void setFlag(int flag) {
		this.FLAG_WG = flag;
	}
	
	public OutputSoapInterceptor() {
		System.out.println("***Snail*** - Create OutputSoapInterceptor Success!");
	
		String strProjectPath = XmlCipherUtil.getProjectPath();
		System.out.println("ProjectPath: " + strProjectPath);
		
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
		
		//出站消息为true，不进行拦截
		Boolean outbound = (Boolean)ctx.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if(!outbound) {
			return true;		
		}
		
		log.trace("***HUJQ*** - 消息拦截成功-出站，查找服务提供者地址信息");
		String ServerURL = (String)ctx.get("javax.xml.ws.service.endpoint.address");
		
		String IP = "", Port = "";
		if(ServerURL != null) {
			//服务调用请求消息
			String ServiceString = ServerURL.substring(ServerURL.indexOf("//") + 2, ServerURL.length());
			String URLString = ServiceString.substring(0, ServiceString.indexOf('/'));
			int sep = URLString.indexOf(':');
			if(sep != -1){
				IP = URLString.substring(0, sep);
				Port = URLString.substring(sep + 1, URLString.length());
			}
			else
				IP = URLString;
			
			log.trace("服务提供者IP地址：" + IP + "; 服务提供者端口号：" + Port);					
		}
		else {
			log.trace("对端地址注入：" + IP + "：" + Port);
			IP = DESTHOST;
			Port = DESTPORT;
		}
		
		log.trace("***HUJQ*** - 根据配置文件，查找密码综合应用网关地址信息");
		
		String strProjectPath = XmlCipherUtil.getProjectPath();
		String strConfigurePath = strProjectPath + CONFIGUREFILE;
		log.debug("ProxyConfig Path: " + strConfigurePath);
		
		ProxyConfig config = ProxyConfig.getInstance(strConfigurePath);
		ProxyStruct struct = config.findProxyConfig(IP, Port);
		
		if(FLAG_WG == 1) {
			if(struct.ProxyHost != null && struct.ProxyPort != null){
				String strProxy = struct.ProxyHost;
				String strPort = struct.ProxyPort;
				System.setProperty("http.proxySet", "true");
				System.setProperty("http.proxyHost", strProxy);
				System.setProperty("http.proxyPort", strPort);
				
				log.trace("网关代理IP地址：" + strProxy + "; 网关代理端口号：" + strPort);					
			}
		}
		
		SOAPMessage soapMessage = ctx.getMessage();
		Document doc = null;
		try {
			doc = soapMessage.getSOAPPart().getEnvelope().getOwnerDocument();
		} catch (SOAPException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		log.trace("***HUJQ*** - 解析加密标签");
		SecurityPolicyParser policyParser = new SecurityPolicyParser(doc, struct);
		int rst = policyParser.parse();
		if(rst != 0)
			return false;
		
		SecurityPolicyInfo policyInfo = policyParser.getSecurityPolicyInfo();
		
		//为SOAP消息头中配置Actor属性信息
		String strActor = "";
		
		log.trace("***HUJQ*** - 对SOAP消息进行安全报文的封装");
		
		//对SOAP消息进行安全报文的封装
		SoapSecurityBuilder builder = new SoapSecurityBuilder(policyInfo, strActor);
		try {
			builder.setActor(LOCALHOST, struct.ProxyHost);
			doc = builder.build();
			
		} catch (WSAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		String strResultSoapFilePath = strProjectPath + "/temp/EnResultSoap.xml";
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
