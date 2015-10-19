package org.nci.xml.security.implement;

import java.io.File;
import java.net.MalformedURLException;
import java.security.Key;
import java.security.PrivateKey;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo_EnvelopSymm;
import org.apache.xml.security.keys.KeyInfo_LocalSymm;
import org.apache.xml.security.keys.KeyInfo_TransSymm;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Base64;
import org.nci.csp.CSP;
import org.nci.xml.security.contexts.ElementEncContext;
import org.nci.xml.security.contexts.ElementSignContext;
import org.nci.xml.security.contexts.IXmlAppContext;
import org.nci.xml.security.contexts.LocalSymmContext;
import org.nci.xml.security.contexts.TransEnvelopContext;
import org.nci.xml.security.contexts.TransSymmContext;
import org.nci.xml.security.interfaces.IXmlEncSign;
import org.nci.xml.security.key.Key_v810;
import org.nci.xml.security.key.PublicKey_v810;
import org.nci.xml.security.util.OptionSwitch;
import org.nci.xml.security.util.SignatureContext;
import org.nci.xml.security.util.XmlCipherContext;
import org.nci.xml.security.util.XmlCipherUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XmlEncSign implements IXmlEncSign {

	static {
        org.apache.xml.security.Init.init();
    }
	
	static org.apache.commons.logging.Log log = 
	        org.apache.commons.logging.LogFactory.getLog(XmlEncSign.class.getName());
	
	Element _returnElement = null;
	
	IXmlAppContext m_appContext = null;
	public XmlEncSign(IXmlAppContext context)
	{
		m_appContext = context;
	}
	
	@Override
	public Document OpenXmlFile(String path) {
	
		return XmlCipherUtil.ImportXmlFile(path);
	}

	@Override
	public long EncryptByName(Document doc, String eleName,
			ElementEncContext encArg) throws Exception {
		
		/*
	     * Let us encrypt the contents/elements of the document element.
	     */
		log.trace("调用EncryptByName方法进行元素加密操作");
		Element rootElement = doc.getDocumentElement();
		
		Element element;
		if(rootElement.getLocalName().equals(eleName)){
			element = rootElement;
		}
		else {
			NodeList nl = rootElement.getElementsByTagName(eleName);
		    //暂时先不考虑有多个同名元素的情况
			if(nl.getLength() > 1){
				System.out.println("Document has more than one element which is named eleName");
		    	log.error("***ERROR*** - 方法EncryptByName暂不支持多个同名元素存在的情况，请选择其他接口进行加密操作");
		    	return -1;
		    }
			element = (Element)(rootElement.getElementsByTagName(eleName).item(0));
		}
		
		long ret = EncryptElement(doc, element, encArg);
		
		log.trace("调用EncryptByName方法完成元素加密操作");
		return ret;
	}

	@Override
	public long EncryptElement(Document doc, Element element,
			ElementEncContext encArg) throws Exception {
		// TODO Auto-generated method stub
		
		/*
	     * Let us encrypt the contents/elements of the document element.
	     */
		log.trace("调用EncryptElement方法进行元素加密操作");
		
		long ret = 0;
		if(m_appContext instanceof LocalSymmContext) {
			ret = EncryptElement_LocalSymm(doc, element, encArg);
		} else if(m_appContext instanceof TransEnvelopContext) {
			ret = EncryptElement_TransEnvelop(doc, element, encArg);
		} else if(m_appContext instanceof TransSymmContext) {
			ret = EncryptElement_TransSymm(doc, element, encArg);
		}
		
		log.trace("调用EncryptElement方法完成元素加密操作");
		return ret;
	}

	@Override
	public long EncryptElements(Document doc, List<Element> elements,
			ElementEncContext encArg) {
		// TODO Auto-generated method stub
		return 0;
	}

	public long EncryptElement_LocalSymm(Document doc, Element element,
			ElementEncContext encArg) throws Exception {
		
		String algorithmURI = XmlCipherContext.MY_810Cipher_XML;
		
		log.trace("开始进行本地加密操作");
		XMLCipher xmlCipher = XMLCipher.getInstance(algorithmURI);
		
		String localDeviceID = "";
		if(OptionSwitch.bDEBUG15XML)
			localDeviceID = "DEBUG-SRC";
		else
			localDeviceID = XmlCipherUtil.GetLocalMMID();
		
		Key_v810 symmetricKey = new Key_v810();
		symmetricKey.setOpID(m_appContext.getOperateID());
		symmetricKey.setSrcDevice(localDeviceID);	
		symmetricKey.setDstDevice(localDeviceID);

		//数据所提供的临时固定IV
		String strIV = "";
    	if(OptionSwitch.bDEBUG15XML)
    		 strIV = "6i22Q3/36K6l7PlJvp/3Iw==";
    	else {
    		byte[] pRandom = new byte[16];
			int ret = CSP.GenRandom(16, pRandom);
			if(ret != 0)
				log.error("***HUJQ*** - 获取随机数作为IV失败！");
			
			strIV = Base64.encode(pRandom);
    	}
		symmetricKey.setIV(strIV);
		
		log.trace("执行加密初始化操作");
		xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);
	    
		log.trace("构造KeyInfo字段");
		KeyInfo_LocalSymm keyinfo = new KeyInfo_LocalSymm(doc);
		keyinfo.setKeyName(localDeviceID);
		keyinfo.setIV(strIV);
				
		xmlCipher.getEncryptedData().setKeyInfo(keyinfo);
	    	    
	    /*
	     * doFinal -
	     * "true" below indicates that we want to encrypt element's content
	     * and not the element itself. Also, the doFinal method would
	     * modify the document by replacing the EncrypteData element
	     * for the data to be encrypted.
	     */
		log.trace("执行加密操作");
		xmlCipher.doFinal(doc, element, encArg.contentMode);

		log.trace("完成本地加密操作");
		return 0;
	}
	
	public long EncryptElement_TransEnvelop(Document doc, Element element,
			ElementEncContext encArg) throws Exception {
		
		String algorithmURI = XmlCipherContext.MY_810Cipher_XML;
		
		log.trace("开始进行数字信封加密操作");
		
		//获得用户传入的对端设备标识
		byte[] peerCert = ((TransEnvelopContext) m_appContext).getPeerCert();
		byte[] peerPK = XmlCipherUtil.getPublicKey(peerCert);

		//用于加密对称密钥的公钥数据
		Key pk_v810 = new PublicKey_v810(peerPK);
		((PublicKey_v810) pk_v810).setOperateID(m_appContext.getOperateID());
		
		KeyGenerator keyGenerator = KeyGenerator.getInstance("Project810KeyGenerator_Xml");
		keyGenerator.init(20);
		Key symmetricKey = keyGenerator.generateKey();
		
		log.trace("执行密钥封装初始化操作");
		XMLCipher xmlCipher_wrapKey = XMLCipher.getInstance(XmlCipherContext.MY_810Cipher_XML_WrapKey);
		xmlCipher_wrapKey.init(XMLCipher.WRAP_MODE, pk_v810);
		
		log.trace("执行密钥封装操作");
		EncryptedKey ek = xmlCipher_wrapKey.encryptKey(doc, symmetricKey);
		
		log.trace("执行加密初始化操作");
		XMLCipher xmlCipher = XMLCipher.getInstance(algorithmURI);
		xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);

		log.trace("构造KeyInfo字段");
		KeyInfo_EnvelopSymm keyinfo = new KeyInfo_EnvelopSymm(doc);
		keyinfo.add(ek);
		xmlCipher.getEncryptedData().setKeyInfo(keyinfo);
		
	    /*
	     * doFinal -
	     * "true" below indicates that we want to encrypt element's content
	     * and not the element itself. Also, the doFinal method would
	     * modify the document by replacing the EncrypteData element
	     * for the data to be encrypted.
	     */
		log.trace("执行加密操作");
		xmlCipher.doFinal(doc, element, encArg.contentMode);

		log.trace("完成本地加密操作");
		return 0;
	}
	
	public long EncryptElement_TransSymm(Document doc, Element element,
			ElementEncContext encArg) throws Exception {
		String algorithmURI = XmlCipherContext.MY_810Cipher_XML;
		
		log.trace("开始进行端端加密操作");
		XMLCipher xmlCipher = XMLCipher.getInstance(algorithmURI);
		
		//获得用户传入的对端设备标识
		String peerDeviceID = ((TransSymmContext) m_appContext).getPeerDevid().toString();
		
		//获得本端密码机标识
		String localDeviceID = "";
		if(OptionSwitch.bDEBUG15XML)
			localDeviceID = "DEBUG-SRC";
		else
			localDeviceID = XmlCipherUtil.GetLocalMMID();
		
		Key_v810 symmetricKey = new Key_v810();
		symmetricKey.setOpID(m_appContext.getOperateID());
		symmetricKey.setSrcDevice(localDeviceID);
    	symmetricKey.setDstDevice(peerDeviceID);
    	
		//数据所提供的临时固定IV
    	String strIV = "";
    	if(OptionSwitch.bDEBUG15XML)
    		 strIV = "6i22Q3/36K6l7PlJvp/3Iw==";
    	else {
    		byte[] pRandom = new byte[16];
			int ret = CSP.GenRandom(16, pRandom);
			if(ret != 0)
				log.error("***HUJQ*** - 获取随机数作为IV失败！");
			
			strIV = Base64.encode(pRandom);
    	}
    	symmetricKey.setIV(strIV);
    	
		log.trace("执行加密初始化操作");
		xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);
    	
		log.trace("构造KeyInfo字段");
		KeyInfo_TransSymm keyinfo = new KeyInfo_TransSymm(doc);
		keyinfo.setKeyName(localDeviceID, peerDeviceID);
		keyinfo.setIV(strIV);
		xmlCipher.getEncryptedData().setKeyInfo(keyinfo);
	    
	    /*
	     * doFinal -
	     * "true" below indicates that we want to encrypt element's content
	     * and not the element itself. Also, the doFinal method would
	     * modify the document by replacing the EncrypteData element
	     * for the data to be encrypted.
	     */
		log.trace("执行加密操作");
		xmlCipher.doFinal(doc, element, encArg.contentMode);
		
		log.trace("完成端端加密操作");
		return 0;
	}

	/**
	 * 修改过程说明：
	 * 1、对XML文档的签名也应该增加ID-URI属性
	 * 2、对源文档部分元素的签名
	 * 3、封外签名的实现
	 */
	@Override
	public long SignByName(Document doc, String eleName,
			ElementSignContext encArg) {
		
		// TODO Auto-generated method stub
		SignatureContext.GetInstance().SetSignatureType(encArg.signType);
		SignatureContext.GetInstance().SetDocument(doc);
		
		/*
		 * Select the signed elements from document
		 * */
		log.trace("调用SignByName方法进行数字签名操作");
		
		Element rootElement = doc.getDocumentElement();
		Element element = null;
		
		if(rootElement.getLocalName().equals(eleName)) {
			element = rootElement;
	    }
		else {
	    	NodeList nl = rootElement.getElementsByTagName(eleName);
	    	//暂时先不考虑有多个同名元素的情况
	    	if(nl.getLength() > 1){
	    		System.out.println("Document has more than one element which is named eleName");
		    	log.error("***ERROR*** - 方法SignByName暂不支持多个同名元素存在的情况，请选择其他接口进行签名操作");
		    	return -1;
		    }
	    	element = (Element)(rootElement.getElementsByTagName(eleName).item(0));
	    }
		
		try {
			//进行签名处理工作
			if(encArg.signType == XmlCipherUtil.SIGNATURETYPE_ENVELOPED){
				return SignUsingEnveloped(doc, element, encArg);
			}
			else if(encArg.signType == XmlCipherUtil.SIGNATURETYPE_ENVELOPING){
				return SignUsingEnveloping(doc, element, encArg);
			}
		} catch (XMLSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		log.trace("调用SignByName方法完成数字签名操作");
		return 0;
	}

	@Override
	public long SignElement(Document doc, Element element,
			ElementSignContext encArg) {
		// TODO Auto-generated method stub
		
		/*
		 * Select the signed elements from document
		 * */
		log.trace("调用SignElement方法进行数字签名操作");
		
		try {
			//进行签名处理工作
			if(encArg.signType == XmlCipherUtil.SIGNATURETYPE_ENVELOPED){
				return SignUsingEnveloped(doc, element, encArg);
			}
			else if(encArg.signType == XmlCipherUtil.SIGNATURETYPE_ENVELOPING){
				return SignUsingEnveloping(doc, element, encArg);
			}
		} catch (XMLSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		log.trace("调用SignElement方法完成数字签名操作");
		return 0;
	}

	@Override
	public long SignElements(Document doc, List<Element> elements,
			ElementSignContext encArg) {
		// TODO Auto-generated method stub
		return 0;
	}
	
	private long SignUsingEnveloped(Document doc, Element element,
			ElementSignContext encArg) throws XMLSecurityException {
		
		File signatureFile = new File("signature.xml");
		String BaseURI = "";
		try {
			BaseURI = signatureFile.toURL().toString();
		} catch (MalformedURLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		log.trace("开始进行封内签名处理操作");
		String algorithmURI = XmlCipherContext.ALGO_ID_SIGNATURE_PROJECT810_SIGNATURE_XML;
		
		//The BaseURI is the URI that's used to prepend to relative URIs
		//File signatureFile = new File("signature.xml");
		//String BaseURI = signatureFile.toURL().toString();
		
		//Create an XML Signature object from the document, BaseURI(null) and
		//signature algorithm (in this case DSA)
		log.trace("执行数字签名对象的初始化构造操作");
		XMLSignature sig = new XMLSignature(doc, BaseURI, algorithmURI);
		
		//Append the signature element to the root element before signing because
		//this is going to be an enveloped signature.
		//This means the signature is going to be enveloped by the document.
		//Two other possible forms are enveloping where the document is inside the
		//signature and detached where they are seperate.
		//Note that they can be mixed in 1 signature with seperate references as
		//shown below.
		element.appendChild(sig.getElement());
		
		//sig.getSignedInfo().addResourceResolver(new org.apache.xml.security.utils.resolver.implementations.OfflineResolver());
		
		XMLSignatureInput input = new XMLSignatureInput(element);
		sig.getSignedInfo().addResourceResolver(new org.apache.xml.security.utils.resolver.implementations.ResolverAnonymous(input));

		log.trace("执行数据规范化操作");
		{
			//create the transforms object for the Document/Reference
			Transforms transforms = new Transforms(doc);

			try {
				//First we have to strip away the signature element (it's not part of the
				//signature calculations). The enveloped transform can be used for this.
				transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);

				//Part of the signature element needs to be canonicalized. It is a kind
				//of normalizing algorithm for XML. For more information please take a
				//look at the W3C XML Digital Signature webpage.
				transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
				
				sig.addDocument(null, transforms, XmlCipherContext.ALGO_ID_DIGEST_PROJECT810_DIGEST_XML);
				
			} catch (TransformationException e) {
				e.printStackTrace();
			} catch (XMLSignatureException e) {
				e.printStackTrace();
			}
		}

		{
			PublicKey_v810 pk810 = new PublicKey_v810();
			sig.addKeyInfo(pk810);

			PrivateKey privateKey = null;
			
			System.out.println("执行数字签名操作");
			try {
				sig.sign(privateKey);
			} catch (XMLSignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			System.out.println("完成数字签名操作");	
		}
		
		_returnElement = sig.getElement();
		return 0;
	}
	
	private long SignUsingEnveloping(Document doc, Element element,
			ElementSignContext encArg) throws XMLSecurityException{
		
		File signatureFile = new File("signature.xml");
		String BaseURI = "";
		try {
			BaseURI = signatureFile.toURL().toString();
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		Node ParentNode = element.getParentNode();
		
		log.trace("开始进行封外签名处理操作");
		String algorithmURI = XmlCipherContext.ALGO_ID_SIGNATURE_PROJECT810_SIGNATURE_XML;	    
	   
		//根据封外签名的格式构造新文档
		Document envelopingDocument = null;
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			envelopingDocument = db.newDocument();
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//The BaseURI is the URI that's used to prepend to relative URIs
		//File signatureFile = new File("signature.xml");
		//String BaseURI = signatureFile.toURL().toString();
			
		//Create an XML Signature object from the document, BaseURI(null) and
		//signature algorithm (in this case DSA)
		log.trace("执行数字签名对象的初始化构造操作");
		XMLSignature sig = new XMLSignature(envelopingDocument, BaseURI, algorithmURI);
			
		//新建根节点，将signature作为根元素插入到根节点中
		Node adoptNode = envelopingDocument.adoptNode(sig.getElement());
		envelopingDocument.appendChild(adoptNode);
			
		ObjectContainer obj = new ObjectContainer(envelopingDocument);
			
		Node adoptElement = envelopingDocument.adoptNode(element);
		obj.appendChild(adoptElement);
		sig.appendObject(obj);
		
		//Append the signature element to the root element before signing because
		//this is going to be an enveloped signature.
		//This means the signature is going to be enveloped by the document.
		//Two other possible forms are enveloping where the document is inside the
		//signature and detached where they are seperate.
		XMLSignatureInput input = new XMLSignatureInput(adoptElement);
		sig.getSignedInfo().addResourceResolver(new org.apache.xml.security.utils.resolver.implementations.ResolverAnonymous(input));

		log.trace("执行数据规范化操作");
		{
			//create the transforms object for the Document/Reference
			Transforms transforms = new Transforms(envelopingDocument);

			try {
				//First we have to strip away the signature element (it's not part of the
				//signature calculations). The enveloped transform can be used for this.
				//transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);

				//Part of the signature element needs to be canonicalized. It is a kind
				//of normalizing algorithm for XML. For more information please take a
				//look at the W3C XML Digital Signature webpage.
				transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
				
				//Add the above Document/Reference
				sig.addDocument(null, transforms, XmlCipherContext.ALGO_ID_DIGEST_PROJECT810_DIGEST_XML);
						
			} catch (TransformationException e) {
				e.printStackTrace();
			} catch (XMLSignatureException e) {
				e.printStackTrace();
			}
		}

		{
			PublicKey_v810 pk810 = new PublicKey_v810();
			sig.addKeyInfo(pk810);

			PrivateKey privateKey = null;
			
			System.out.println("执行数字签名操作");
			try {
				sig.sign(privateKey);
			} catch (XMLSignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			Node newAdoptNode = doc.adoptNode(envelopingDocument.getDocumentElement());
			ParentNode.appendChild(newAdoptNode);
			
			System.out.println("完成数字签名操作");	
		}
		
		_returnElement = sig.getElement();
		return 0;
	}
	
	public Element GetResultElementIfNeed() {
		return _returnElement;
	}
	
	@Override
	public long SaveEncryptedFile(Document doc, String encFileName) {
		return XmlCipherUtil.SaveEncryptedFile(doc, encFileName);
	}
}
