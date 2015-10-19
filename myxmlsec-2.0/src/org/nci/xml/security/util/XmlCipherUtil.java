package org.nci.xml.security.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.c14n.Canonicalizer;
import org.doomdark.uuid.UUID;
import org.doomdark.uuid.UUIDGenerator;
import org.nci.csp.CSP;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;

public class XmlCipherUtil {
	
	public static final int SIGNATURETYPE_ENVELOPED = 1;
	public static final int SIGNATURETYPE_ENVELOPING = 2;
	//暂时不用此方法
	public static final int SIGNATURETYPE_DETACHED = 3;
	
	//从文件中导入Document对象，费时操作
	public static Document ImportXmlFile(String xmlPath){
		
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		Document doc;
		dbf.setNamespaceAware(true);
		DocumentBuilder db;
		try {
			db = dbf.newDocumentBuilder();
			doc = db.parse(xmlPath);
		} catch (Exception e) {
			System.out.println("ImportXmlFile Error!");
			return null;
		}
		return doc;
	}
	
	//将Document对象保存到文件中，费时操作
	public static long SaveEncryptedFile(Document doc, String encFileName){
		
		try{
			TransformerFactory factory = TransformerFactory.newInstance();
			Transformer transformer = factory.newTransformer();
			
			DOMSource source = new DOMSource(doc);
			StreamResult result =  new StreamResult(new File(encFileName));
			transformer.transform(source, result);
			
		}catch(TransformerException e){
			return -1;
		}
		return 0;
	}
	
	//使用格式化方法将XML对象转换为字符串，费时操作
	public static String XMLtoStringWithCan (Node n) throws Exception {

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Canonicalizer c14n = Canonicalizer.getInstance
		    (Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);

		byte[] serBytes = c14n.canonicalizeSubtree(n);
		baos.write(serBytes);
		baos.close();

		return baos.toString("UTF-8");
	}
	
	//不使用格式化方法将XML对象转换为字符串
	public static String XMLtoStringWithoutCan(Node n) throws TransformerException {
		
		StringWriter sw = new StringWriter();
		StreamResult sr = new StreamResult(sw);
		
		TransformerFactory factory = TransformerFactory.newInstance();
		Transformer transformer = factory.newTransformer();
		
		DOMSource source = new DOMSource(n);
		transformer.transform(source, sr);
		
		return sr.getWriter().toString();
	}
	
	//将字符串转换为XML对象
	public static Document StringtoXML(String docString) throws Exception {
		
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		
		DocumentBuilder db = dbf.newDocumentBuilder();
		Document doc = db.parse(docString);
		
		return doc;
	}
	
	//生成UUID
	public static String GetUUID() {
		
		UUIDGenerator m_uuidGenerator = UUIDGenerator.getInstance();
		UUID uuid = m_uuidGenerator.generateRandomBasedUUID();
		
		return uuid.toString();
	}

	//获得工程或库路径
	public static String getProjectPath(){
		
		java.net.URL url = XmlCipherUtil.class.getProtectionDomain().getCodeSource().getLocation();
		String filePath= null;
		try{
			filePath = java.net.URLDecoder.decode(url.getPath(), "utf-8");
		}catch(Exception e){
			e.printStackTrace();
		}
		
		if(filePath.endsWith(".jar"))
			filePath = filePath.substring(0, filePath.lastIndexOf("/") + 1);
		
		filePath = filePath.substring(0, filePath.lastIndexOf("/"));
		filePath = filePath.substring(0, filePath.lastIndexOf("/"));
		
		java.io.File file = new java.io.File(filePath);
		filePath = file.getAbsolutePath();
		
		System.out.println("ProjectPath: " + filePath);
		
		return filePath;
	}
	
	//获取本地密码机标识，需要调用cspi接口
	public static String GetLocalMMID() {
		//获取本地密码机标识
		Pointer pMMid = new Memory(4);
		IntByReference pLen = new IntByReference();
		pLen.setValue(4);
		
		int rv = CSP.getLocalMMid(pMMid, pLen);
		if(rv != 0)
			return "";
		
		byte[] mmjid_src = pMMid.getByteArray(0, pLen.getValue());
		String str_mmjid_src = XmlCipherUtil.TransformBinaryMMIdtoFormat(mmjid_src);
		
		return str_mmjid_src;
	}
	
	/**多级安全使用的文电格式标识转换函数
	 * 将本地二进制表示的四位标识转换为六位点分密码标识
	 */
	public static String TransformLocalMMIdto6(byte[] srcMMID, int len){
		
		String MMID32 = "";
		String MMID = "";
		String temp = "00000000";
		
		for(int i = 0; i < len; i++)
		{
			String currStr2 = "";
			
			int temp10 = Integer.parseInt(String.valueOf(srcMMID[i]),10);
			String temp2 = Integer.toBinaryString(temp10);
			
			int currlen2 = temp2.length();
			if(currlen2 < 8)
				currStr2 = temp.substring(0, 8-currlen2) + temp2;
			
			MMID32 += currStr2;
		}
		//System.out.println(MMID32);
		
		//5 3 1 5 6 12
		String frag1 = MMID32.substring(0, 5);
		String frag2 = MMID32.substring(5, 8);
		String frag3 = MMID32.substring(8, 9);
		String frag4 = MMID32.substring(9, 14);
		String frag5 = MMID32.substring(14, 20);
		String frag6 = MMID32.substring(20, 32);
		
		int int1 = Integer.parseInt(frag1, 2);
		int int2 = Integer.parseInt(frag2, 2);
		int int3 = Integer.parseInt(frag3, 2);
		int int4 = Integer.parseInt(frag4, 2);
		int int5 = Integer.parseInt(frag5, 2);
		int int6 = Integer.parseInt(frag6, 2);
		
		MMID = String.valueOf(int1) + "." + String.valueOf(int2) + "."  + String.valueOf(int3) + "."  
				+ String.valueOf(int4) + "."  + String.valueOf(int5) + "."  + String.valueOf(int6);

		return MMID;
	}
	
	/**多级安全使用的文电格式标识转换函数
	 * 将本地六位点分密码标识转换为二进制表示的四位标识
	 */
	public static byte[] TransformLocalMMIdto4(String MMID){
		
		String MMID32 = "";
		byte[] bMMID = new byte[4];
		String temp = "000000000000";
		
		int index = 0;
		for(int i = 1; i <= 6; i++){
			int curr = 0;
			if(i != 6){
				index = MMID.indexOf(".");
				curr = Integer.parseInt(MMID.substring(0, index));
			}else
				curr = Integer.parseInt(MMID);
			
			String currStr2 = Integer.toBinaryString(curr);
			int len = currStr2.length();
			
			switch(i){
				case 1:
					if(len < 5)
						currStr2 = temp.substring(0, 5-len) + currStr2;	
					break;
				case 2:
					if(len < 3)
						currStr2 = temp.substring(0, 3-len) + currStr2;	
					break;
				case 3:
					if(len < 1)
						currStr2 = temp.substring(0, 1-len) + currStr2;	
					break;
				case 4:
					if(len < 5)
						currStr2 = temp.substring(0, 5-len) + currStr2;	
					break;
				case 5:
					if(len < 6)
						currStr2 = temp.substring(0, 6-len) + currStr2;	
					break;
				case 6:
					if(len < 12)
						currStr2 = temp.substring(0, 12-len) + currStr2;	
					break;
			}
						
			MMID32 += currStr2;
			
			if(i!=6)
				MMID = MMID.substring(index + 1, MMID.length());
		}
		
		int frag1 = Integer.parseInt(MMID32.substring(0, 8),2);
		int frag2 = Integer.parseInt(MMID32.substring(9, 16),2);
		int frag3 = Integer.parseInt(MMID32.substring(17, 24),2);
		int frag4 = Integer.parseInt(MMID32.substring(25, 32),2);

		bMMID[0] = (byte) frag1;
		bMMID[1] = (byte) frag2;
		bMMID[2] = (byte) frag3;
		bMMID[3] = (byte) frag4;
		
		return bMMID;
	}
	
	//810标准
	//将二进制表示的四位标识转换为四位分割密码标识
	public static String TransformBinaryMMIdtoFormat(byte[] srcMMID) {
		
		String FormatMMID = "";
		
		for(int i = 0; i < 4; i++)
		{		
			int tempInt = Integer.parseInt(String.valueOf(srcMMID[i]),10);
			String tempStr = String.valueOf(tempInt&0xff);
			
			if(i != 3)
				FormatMMID += tempStr + "-";
			else if(i == 3)
				FormatMMID += tempStr;
		}
		
		return FormatMMID;
	}
	
	//810标准
	//将四位分割密码标识转换为二进制表示的四位标识
	public static byte[] TransformFormatMMIdtoBinary(String MMID) {
		
		byte[] BinaryMMID = new byte[4];
		
		int index = 0;
		for(int i = 0; i < 4; i++){
			int curr = 0;
			if(i != 3){
				index = MMID.indexOf("-");
				curr = Integer.parseInt(MMID.substring(0, index));
			}else
				curr = Integer.parseInt(MMID);
						
			BinaryMMID[i] = (byte) curr;
			
			if(i != 3)
				MMID = MMID.substring(index + 1, MMID.length());
		}
		
		return BinaryMMID;
	}
	
	//证书解析函数，获取公钥
	public static byte[] getPublicKey(byte[] pCertData){
		
		if(OptionSwitch.bHASCERT) {
			
			int CertDataLen = pCertData.length;
			
			byte[] pPubKeyData = new byte[255];
			IntByReference nPubKeyDataLen = new IntByReference();
			nPubKeyDataLen.setValue(255);
		
			int ret = CSP.GetPublicKey(pCertData, CertDataLen, pPubKeyData, nPubKeyDataLen);
			if( ret != 0 ) {
				return null;
			}
			
			int npkdata_len = nPubKeyDataLen.getValue();
			byte[] pubKeyData = new byte[npkdata_len];
			System.arraycopy(pPubKeyData, 0, pubKeyData, 0, npkdata_len);
			
			return pubKeyData;
		}
		else {
			return pCertData;
		}
	}
	
	public static void main(String arg[]) {
		
		byte[] testMMID = new byte[]{0x11, 0x22, 0x33, 0x44};
		
		String strTestMMID = TransformBinaryMMIdtoFormat(testMMID);
		System.out.println("String MMID : " + strTestMMID);
		
		byte[] bTestMMID = TransformFormatMMIdtoBinary(strTestMMID);
		System.out.println("Binary MMID length : " + bTestMMID.length);
	}
}
