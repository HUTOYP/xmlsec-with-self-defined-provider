package org.nci.soap.security.test;

import org.apache.log4j.PropertyConfigurator;
import org.nci.csp.CSP;
import org.nci.soap.policy.SecurityPolicyInfo;
import org.nci.soap.policy.SecurityPolicyParser;
import org.nci.soap.security.engine.SoapSecurityBuilder;
import org.nci.soap.security.engine.SoapSecurityValidator;
import org.nci.soap.security.exception.WSAccessException;
import org.nci.soap.security.util.ProxyConfig;
import org.nci.soap.security.util.ProxyStruct;
import org.nci.xml.security.implement.XmlEncSign;
import org.nci.xml.security.util.OptionSwitch;
import org.nci.xml.security.util.XmlCipherUtil;
import org.w3c.dom.Document;

public class SoapSecurityTest {
	
	static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(XmlEncSign.class.getName());
	
	
	/** Test **/
	public final static String SOAPFILE = "/temp/PlainSoap.xml";
	public final static String SOAPFILE_sjs = "/temp/big1.xml";
	
	public final static String SECURITYSOAPFILE = "/temp/CipherSoap.xml";
	public final static String SECURITYSOAPFILE_sjs = "/temp/xml_enc.xml";
	
	public final static String CONFIGUREFILE = "/config/ProxyConfig.xml";
	public final static String LOCALHOST = "28.28.24.206";
	/** Test End **/	
	
	public static void main(String arg[])
	{
		//CSP初始化，多次初始化并不会有任何不良影响
		byte[] bApp = "XML-SOAP ENCRYPTION".getBytes();
		CSP.SetOperateDevice(bApp);
		//*****************************************************************
		
		//不予许Base64自动换行
		System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");
		PropertyConfigurator.configure("./log4j.properties");

		String strProjectPath = XmlCipherUtil.getProjectPath();
		String strConfigurePath = strProjectPath + CONFIGUREFILE;
		log.debug("ProxyConfig Path: " + strConfigurePath);
		
		String strSecuritySoapFilePath = strProjectPath + SECURITYSOAPFILE_sjs;
		
		Document doc = null;
		
		if(!OptionSwitch.bONLYVALIDATE) {
			
			System.out.println("Build Starting.....");
			ProxyConfig config = ProxyConfig.getInstance(strConfigurePath);
			ProxyStruct struct = config.findProxyConfig("28.28.23.202", "8418");
			
			String strSoapFilePath = strProjectPath + SOAPFILE;
			doc = XmlCipherUtil.ImportXmlFile(strSoapFilePath);
			
			SecurityPolicyParser policyParser = new SecurityPolicyParser(doc, struct);
			
			int ret = policyParser.parse();
			if(ret != 0){
				log.debug("Security policy parse error in soap!");
				return;
			}
			
			SecurityPolicyInfo policyInfo = policyParser.getSecurityPolicyInfo();
			
			SoapSecurityBuilder securityBuilder = new SoapSecurityBuilder(policyInfo);
			try {
				securityBuilder.setActor(LOCALHOST, struct.ProxyHost);
				Document securitydoc = securityBuilder.build();
			
				XmlCipherUtil.SaveEncryptedFile(securitydoc, strSecuritySoapFilePath);
				
			} catch (WSAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			System.out.println("Build Finish");
		}
		
		System.out.println("Validate Starting...");
		
		doc = XmlCipherUtil.ImportXmlFile(strSecuritySoapFilePath);
		
		String localip = "9.30.1.200";
		
		SoapSecurityValidator securityValidator = new SoapSecurityValidator(doc, localip);
		Document resultdoc = securityValidator.validate();
		
		String strResultSoapFilePath = strProjectPath + "/temp/ResultSoap.xml";
		XmlCipherUtil.SaveEncryptedFile(resultdoc, strResultSoapFilePath);
		
		System.out.println("Validate Finish");
	}
}
