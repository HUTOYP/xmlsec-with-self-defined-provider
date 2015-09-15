package org.nci.xml.security.test;

import java.util.Calendar;

import org.apache.log4j.PropertyConfigurator;
import org.nci.csp.CSP;
import org.nci.xml.security.contexts.ElementEncContext;
import org.nci.xml.security.contexts.ElementSignContext;
import org.nci.xml.security.contexts.IXmlAppContext;
import org.nci.xml.security.implement.AppContextFactory;
import org.nci.xml.security.implement.XmlCipherFactory;
import org.nci.xml.security.interfaces.IXmlDecVer;
import org.nci.xml.security.interfaces.IXmlEncSign;
import org.nci.xml.security.util.XmlCipherUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class XmlSecurity {

	public static String strVersion = "V0.1.0";
	public static String strCopyRight = "软件版权及最终解释权归中国电子科技集团公司第十五研究所所有。";
	public static String strAbout = "\r\n软件名称： \"810工程\"密码服务中间件XML加密构件-XML文档加密工具\r\n" +
									"软件版本： " + strVersion + "\r\n" +
									"软件版权： " + strCopyRight + "\r\n";
	
	public static String strUsage = "\r\n用法： XmlSecurity [options]\r\n" + 
							"\r\nOptions 罗列如下：\r\n" + 
							"    -type   \t指定工作类型：1为加密；2为解密；3为签名；4为验签\r\n" +
							"    -subtype\t加密子类型：1为本地存储加密；2为端端传输加密；3为数字信封加密(仅用于加密)\r\n" + 
							"    -mode   \t指定工作模式，作为工作类型的子类型，解密/验签时此命令无效\r\n" +
							"            \t进行加密操作时，1为元素加密；2为内容加密（默认值为 1）\r\n" +
							"            \t进行签名操作时，1为封内签名；2为封外签名（默认值为 1）\r\n" +
							"    -path   \t待操作XML文档位置\r\n" +
							"    -target \t待操作XML元素名称（解密/验签时此命令无效，默认值为对XML文档根节点进行处理）\r\n" +
							"    -output \t处理结果输出位置（默认值为./XmlSecurityOutput.xml）\r\n" +
							"    -debug  \t记录Debug级别调试日志\r\n" +
							"    -time   \t显示操作时长(ms)\r\n";

	private static int m_iType;
	private static int m_iSubType;
	private static int m_iMode;
	private static String m_strPath;
	private static String m_strTarget;
	private static String m_strOutput;
	private static boolean m_bShowDebugLog;
	private static boolean m_bShowTime;
	
	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		
		//CSP初始化，多次初始化并不会有任何不良影响
		byte[] bApp = "XML-SOAP ENCRYPTION".getBytes();
		CSP.SetOperateDevice(bApp);
		//*****************************************************************
		
		//不予许Base64自动换行
		System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");
		
		if(!m_bShowDebugLog)
			PropertyConfigurator.configure("./log4j.properties");
		else
			PropertyConfigurator.configure("./log4j.debug.properties");
		
		if(!processArgs(args)){
			return;
		}
		
		if(m_strPath == null || m_strPath == "") {
			System.out.println("ParamError： 未指定XML文档的导入路径");
			return;
		}		
		
		long millis_begin = Calendar.getInstance().getTimeInMillis();
		
		if(m_iType == 1) {
			EncryptData();
		} else if(m_iType == 2) {
			DecryptData();
		} else if(m_iType == 3) {
			SignatureData();
		} else if(m_iType == 4) {
			ValidateData();
		} else {
			System.out.println("ParamError： 未定义的工作类型： " + m_iType);
		}
		
		long millis_finish = Calendar.getInstance().getTimeInMillis();
		if(m_bShowTime) {
			System.out.println("执行时间为： " + (millis_finish - millis_begin));
		}
	}
	
	public static void EncryptData() throws Exception {

		IXmlAppContext appContext = null;
		if(m_iSubType == 1)
			appContext = AppContextFactory.createLocalSymmContext(1);
		else if(m_iSubType == 2)
			appContext = AppContextFactory.createTransSymmContext(1, "2-39-192-152");
		else if(m_iSubType == 3)
			appContext = AppContextFactory.createTransEnvelopContext(1, "DEBUG-DST-CERT".getBytes());

		IXmlEncSign xmlencsign = XmlCipherFactory.CreateEncSig(appContext);
		
		Document doc = xmlencsign.OpenXmlFile(m_strPath);
		if(doc == null) {
			System.out.println("Error： XML文档解析失败");
			return;
		}

		ElementEncContext encArg = null;
		if(m_iMode == 1)
			encArg = new ElementEncContext(false);
		else if(m_iMode == 2)
			encArg = new ElementEncContext(true);
		else {
			System.out.println("ParamError： 未定义的工作模式： " + m_iMode);
			return;
		}
		
		//现阶段只支持根据唯一元素名称加密的方式
		xmlencsign.EncryptByName(doc, m_strTarget, encArg);

		xmlencsign.SaveEncryptedFile(doc, m_strOutput);		
		System.out.println("handle encrypt success!");
	}
	
	public static void DecryptData() {
		
		IXmlDecVer xmldecver = XmlCipherFactory.CreateDecVer();
		
		Document doc = xmldecver.OpenXmlFile(m_strPath);
		if(doc == null) {
			System.out.println("Error： XML文档解析失败");
			return;
		}
		
		xmldecver.Decrypt(doc);
		
		xmldecver.SaveDecryptedFile(doc, m_strOutput);		
		System.out.println("handle decrypt success!");
	}
	
	public static void SignatureData() {
		
		IXmlAppContext appContext = AppContextFactory.createTransSymmContext(1, null);
		
		IXmlEncSign xmlencsign = XmlCipherFactory.CreateEncSig(appContext);
		
		Document doc = xmlencsign.OpenXmlFile(m_strPath);
		if(doc == null) {
			System.out.println("Error： XML文档解析失败");
			return;
		}
		
		ElementSignContext signArg = new ElementSignContext();
		signArg.id = "";
		
		if(m_iMode == 1)
			signArg.signType = XmlCipherUtil.SIGNATURETYPE_ENVELOPED;
		else if(m_iMode == 2)
			signArg.signType = XmlCipherUtil.SIGNATURETYPE_ENVELOPING;
		else {
			System.out.println("ParamError： 未定义的工作模式： " + m_iMode);
			return;
		}	
		
		xmlencsign.SignByName(doc, m_strTarget, signArg);
		
		Element signature = null;
		if(signArg.signType == XmlCipherUtil.SIGNATURETYPE_ENVELOPED) {
			signature = xmlencsign.GetResultElementIfNeed();
		}
		
		xmlencsign.SaveEncryptedFile(doc, m_strOutput);
		System.out.println("handle Signature success!");
	}
	
	public static void ValidateData() {
		
		IXmlDecVer xmldecver = XmlCipherFactory.CreateDecVer();
		
		Document doc = xmldecver.OpenXmlFile(m_strPath);
		if(doc == null) {
			System.out.println("Error： XML文档解析失败");
			return;
		}
		
		long ret = xmldecver.Verify(doc);
		if(ret != 0) {
			System.out.println("handle Verify failure!");
			return;
		}
		
		xmldecver.SaveDecryptedFile(doc, m_strOutput);
		System.out.println("handle Verify success!");
	}
	
	public static boolean processArgs(String[] args){
		
		m_iType = 0;
		m_iSubType = 0;
		m_iMode = 1;
		m_strPath = "";
		m_strTarget = "";
		m_strOutput = "./XmlSecurityOutput.xml";
		m_bShowDebugLog = false;
		m_bShowTime = false;
		
		if(args.length == 0) {
			System.out.println("请使用 -help 命令行选项查看使用方法");
			return false;
		}
		
		for(int i = 0; i < args.length; i++) {
			
			String arg = args[i];
			
			if(arg.equalsIgnoreCase("-help") || arg.equalsIgnoreCase("help") 
					|| arg.equalsIgnoreCase("-?") || arg.equalsIgnoreCase("?")) {
				System.out.println(strUsage);
				return false;
			} else if(arg.equalsIgnoreCase("-type")) {
				i++; m_iType = Integer.parseInt(args[i]);
			} else if(arg.equalsIgnoreCase("-subtype")) {
				i++; m_iSubType = Integer.parseInt(args[i]);
			} else if(arg.equalsIgnoreCase("-mode")) {
				i++; m_iMode = Integer.parseInt(args[i]);
			} else if(arg.equalsIgnoreCase("-path")) {
				i++; m_strPath = args[i];
			} else if(arg.equalsIgnoreCase("-target")) {
				i++; m_strTarget = args[i];
			} else if(arg.equalsIgnoreCase("-output")) {
				i++; m_strOutput = args[i];
			} else if(arg.equalsIgnoreCase("-debug")) {
				m_bShowDebugLog = true;
			} else if(arg.equalsIgnoreCase("-time")) {
				m_bShowTime = true;
			} else if(arg.equalsIgnoreCase("-version")) {
				System.out.println(strVersion);
				return false;
			} else if(arg.equalsIgnoreCase("-about")) {
				System.out.println(strAbout);
				return false;
			} else {
				System.out.println("ParamError: Unknown Command !");
				return false;
			}
		}
		
		return true;
	}
}