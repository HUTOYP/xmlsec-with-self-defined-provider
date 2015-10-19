package org.nci.xml.security.test;

import java.util.ArrayList;
import java.util.Calendar;

import org.nci.xml.security.contexts.ElementEncContext;
import org.nci.xml.security.contexts.IXmlAppContext;
import org.nci.xml.security.implement.AppContextFactory;
import org.nci.xml.security.implement.XmlCipherFactory;
import org.nci.xml.security.interfaces.IXmlEncSign;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class XMLSecurityPerformanceTest {

	private static final int CircleTimes = 20;
	
	public static void main(String[] args) throws Exception {
		
		if(args.length < 2)
		{
			System.out.println("args was on size error!");
			return;
		}
		
		byte[] peerDevid = new byte[]{0x11, 0x22, 0x33, 0x44};
		IXmlAppContext appContext = AppContextFactory.createTransSymmContext(0, peerDevid.toString());
		
		IXmlEncSign xmlencsign = XmlCipherFactory.CreateEncSig(appContext);
		
		ArrayList<Document> docList = new ArrayList<Document>();
		ArrayList<Element> eleList = new ArrayList<Element>();
		for(int i = 0; i < CircleTimes; i++) {
			Document doc = xmlencsign.OpenXmlFile(args[0]);
			if(doc == null)
				return;
			
			Element rootElement = doc.getDocumentElement();			
			String eleName = "person";
			
			Element element = null;
			if(rootElement.getLocalName().equals("")){
				element = rootElement;
			}
			else {
				NodeList nl = rootElement.getElementsByTagName(eleName);
			    //暂时先不考虑有多个同名元素的情况
				if(nl.getLength() > 1){
					System.out.println("Document has more than one element which is named eleName");
			    	return;
			    }
				element = (Element)(rootElement.getElementsByTagName(eleName).item(0));
			}
			
			docList.add(doc);
			eleList.add(element);
		}
		
		long millis = Calendar.getInstance().getTimeInMillis();
		System.out.println("开始时间： " + millis);
		
		for(int i = 0; i < CircleTimes; i++) {
			//开始加密
			ElementEncContext encArg = new ElementEncContext(false);
			xmlencsign.EncryptElement(docList.get(i), eleList.get(i), encArg);
		}
		millis = Calendar.getInstance().getTimeInMillis();
		System.out.println("结束时间： " + millis);
		
		System.out.println("handle encrypt success!");
	}
}
