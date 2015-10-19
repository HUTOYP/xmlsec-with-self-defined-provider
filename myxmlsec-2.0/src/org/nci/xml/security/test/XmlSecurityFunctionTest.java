package org.nci.xml.security.test;

import java.util.Calendar;
import org.apache.log4j.PropertyConfigurator;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.nci.xml.security.contexts.*;
import org.nci.xml.security.interfaces.*;
import org.nci.xml.security.implement.*;
import org.nci.xml.security.util.XmlCipherUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class XmlSecurityFunctionTest {
	
	/**
	 * @param args
	 * @throws XMLEncryptionException 
	 */
	public static void main(String[] args) throws XMLEncryptionException {
		// TODO Auto-generated method stub
		// log4j config
		PropertyConfigurator.configure("./log4j.properties");
		
		long millis = Calendar.getInstance().getTimeInMillis();
		System.out.println(millis);
	
		EncryptData_LocalSymm(args);
//		EncryptData_TransEnvelop(args);
//		EncryptData_TransSymm(args);
//		
//		DecryptData(args);
//		
//		SignatureData_Enveloped(args);
//		SignatureData_Enveloping(args);
//		ValidateData(args);
		
		millis = Calendar.getInstance().getTimeInMillis();
		System.out.println(millis);
	}
	
	public static void EncryptData_LocalSymm(String[] args){
		
		if(args.length < 2)
		{
			System.out.println("args was on size error!");
			return;
		}
		
		IXmlAppContext appContext = AppContextFactory.createLocalSymmContext(0);
		
		IXmlEncSign xmlencsign = XmlCipherFactory.CreateEncSig(appContext);
		System.out.println("args[0]: " + args[0]);
		
		Document doc = xmlencsign.OpenXmlFile(args[0]);
		
		if(doc == null)
			return;
		
		ElementEncContext encArg = new ElementEncContext(false);
		try {
			xmlencsign.EncryptByName(doc, "person", encArg);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("args[1]: " + args[1]);
		xmlencsign.SaveEncryptedFile(doc, args[1]);
		
		System.out.println("handle encrypt success!");
	}
	
	public static void EncryptData_TransEnvelop(String[] args){
		
		if(args.length < 2)
		{
			System.out.println("args was on size error!");
			return;
		}
		
		byte[] peerCert = new byte[]{0x11, 0x22, 0x33, 0x44, 0x55};
		IXmlAppContext appContext = AppContextFactory.createTransEnvelopContext(0, peerCert);
		
		IXmlEncSign xmlencsign = XmlCipherFactory.CreateEncSig(appContext);
		System.out.println("args[0]: " + args[0]);
		
		Document doc = xmlencsign.OpenXmlFile(args[0]);
		
		if(doc == null)
			return;
			
		ElementEncContext encArg = new ElementEncContext(false);
		try {
			xmlencsign.EncryptByName(doc, "person", encArg);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("args[1]: " + args[1]);
		xmlencsign.SaveEncryptedFile(doc, args[1]);
		
		System.out.println("handle encrypt success!");
	}

	public static void EncryptData_TransSymm(String[] args){
		
		if(args.length < 2)
		{
			System.out.println("args was on size error!");
			return;
		}
		
		byte[] peerDevid = new byte[]{0x11, 0x22, 0x33, 0x44};
		IXmlAppContext appContext = AppContextFactory.createTransSymmContext(0, peerDevid.toString());
		
		IXmlEncSign xmlencsign = XmlCipherFactory.CreateEncSig(appContext);
		System.out.println("args[0]: " + args[0]);
		
		Document doc = xmlencsign.OpenXmlFile(args[0]);
		
		if(doc == null)
			return;
			
		ElementEncContext encArg = new ElementEncContext(false);
		try {
			xmlencsign.EncryptByName(doc, "person", encArg);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("args[1]: " + args[1]);
		xmlencsign.SaveEncryptedFile(doc, args[1]);
		
		System.out.println("handle encrypt success!");
	}
	
	public static void DecryptData(String[] args){
		
		if(args.length < 2)
		{
			System.out.println("args was on size error!");
			return;
		}
		
		IXmlDecVer xmldecver = XmlCipherFactory.CreateDecVer();
		System.out.println("args[1]: " + args[1]);
		Document doc = xmldecver.OpenXmlFile(args[1]);
		if(doc == null)
			return;
		
		xmldecver.Decrypt(doc);
		
		System.out.println("args[0]: " + args[0]);
		xmldecver.SaveDecryptedFile(doc, args[0]);
		
		System.out.println("handle decrypt success!");
	}

	public static void SignatureData_Enveloped(String[] args){
				
		if(args.length < 2)
		{
			System.out.println("args was on size error!");
			return;
		}
		
		IXmlEncSign xmlencsign = XmlCipherFactory.CreateEncSig(null);
		System.out.println("args[0]: " + args[0]);
		Document doc = xmlencsign.OpenXmlFile(args[0]);
		if(doc == null)
			return;
		
		ElementSignContext signArg = new ElementSignContext();
		signArg.id = "";
		signArg.signType = XmlCipherUtil.SIGNATURETYPE_ENVELOPED;
				
		try {
			xmlencsign.SignByName(doc, "person", signArg);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		Element signature = xmlencsign.GetResultElementIfNeed();
		
		System.out.println("args[1]: " + args[1]);
		xmlencsign.SaveEncryptedFile(doc, args[1]);
		
		System.out.println("handle Signature success!");
	}
	
	public static void SignatureData_Enveloping(String[] args){
		
		if(args.length < 2)
		{
			System.out.println("args was on size error!");
			return;
		}
		
		IXmlEncSign xmlencsign = XmlCipherFactory.CreateEncSig(null);
		System.out.println("args[0]: " + args[0]);
		Document doc = xmlencsign.OpenXmlFile(args[0]);
		if(doc == null)
			return;
		
		ElementSignContext signArg = new ElementSignContext();
		signArg.id = "";
		signArg.signType = XmlCipherUtil.SIGNATURETYPE_ENVELOPING;
				
		try {
			xmlencsign.SignByName(doc, "person", signArg);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("args[1]: " + args[1]);
		xmlencsign.SaveEncryptedFile(doc, args[1]);
		
		System.out.println("handle Signature success!");
	}
	
	public static void ValidateData(String[] args){
		
		if(args.length < 2)
		{
			System.out.println("args was on size error!");
			return;
		}
		
		IXmlDecVer xmldecver = XmlCipherFactory.CreateDecVer();
		System.out.println("args[1]: " + args[1]);
		Document doc = xmldecver.OpenXmlFile(args[1]);
		if(doc == null)
			return;
		
		xmldecver.Verify(doc);
		
		System.out.println("args[0]: " + args[0]);
		xmldecver.SaveDecryptedFile(doc, args[0]);
		
		System.out.println("handle Verify success!");
	}
}
