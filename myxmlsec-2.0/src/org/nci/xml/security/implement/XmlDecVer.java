package org.nci.xml.security.implement;

import java.io.File;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.nci.soap.security.util.WSSecurityContext;
import org.nci.xml.security.interfaces.IXmlDecVer;
import org.nci.xml.security.key.Key_v810;
import org.nci.xml.security.key.PublicKey_v810;
import org.nci.xml.security.util.XmlCipherUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XmlDecVer implements IXmlDecVer {

	static {
        org.apache.xml.security.Init.init();
    }
	
	static org.apache.commons.logging.Log log = 
	        org.apache.commons.logging.LogFactory.getLog(XmlEncSign.class.getName());
	
	@Override
	public Document OpenXmlFile(String path) {
		
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		
		Document document;
		DocumentBuilder db;
		
		try {
			db = dbf.newDocumentBuilder();
			document = db.parse(path);
		} catch (Exception e) {
			System.out.println("ImportXmlFile Error!");
			return null;
		}
		return document;
	}

//	@Override
//	public long DecryptAndVerify(Document doc) {
//		// TODO Auto-generated method stub
//		return 0;
//	}

	@Override
	public long Verify(Document doc) {
		// TODO Auto-generated method stub
		log.trace("Verify - Begin");
		
		File f = new File("signature.xml");
		log.trace("Verify - Call XMLSignature getInstance");
		
		int signatureType = 0;
		NodeList ObjectNodeList = null;
		
		//SignatureContext.GetInstance().SetDocument(doc);
		//HUJQ - 判断是封内签名还是封外签名
		//SignatureContext.GetInstance().SetSignatureType(XmlCipherUtil.SIGNATURETYPE_ENVELOPED);
		
		boolean result= false;
		try {
			
			//Element nscontext = XmlCipherUtil.createDSctx(doc, "ds", Constants.SignatureSpecNS);
			NodeList nl = doc.getElementsByTagName("ds:Signature");
	        //暂时先不考虑有多个同名元素的情况
			Element sigElement = (Element) nl.item(0);
	        
			//自动化判断签名方式是封内签名还是封外签名
			XMLSignatureInput input = null;
			NodeList nodeList = sigElement.getElementsByTagName("ds:Object");
			
			if(nodeList.getLength() != 0) {
				signatureType = XmlCipherUtil.SIGNATURETYPE_ENVELOPING;
				ObjectNodeList = nodeList.item(0).getChildNodes();
				input = new XMLSignatureInput(ObjectNodeList.item(0));
			} else {
				signatureType = XmlCipherUtil.SIGNATURETYPE_ENVELOPED;
				input = new XMLSignatureInput(sigElement.getParentNode());
	        }
			
			XMLSignature signature = new XMLSignature(sigElement, f.toURL().toString());

			//remove 
			//signature.addResourceResolver(new OfflineResolver());
			signature.getSignedInfo().addResourceResolver(new org.apache.xml.security.utils.resolver.implementations.ResolverAnonymous(input));
			
			//之后版本应当存在KeyInfo字段
			KeyInfo ki = signature.getKeyInfo();
			if(ki != null)
				log.debug("Verify - KeyInfo is Exist, Oh, My God !!!???");

			//假设810规范中的PublicKey存在，且存放在Key_v810中
			//PublicKey_v810 publicKey = new PublicKey_v810();
			result = signature.checkSignatureValue(ki.getPublicKey());
			
			if(result) {
				log.trace("check signature is valid (good)");
			} else {
				log.trace("check signature is invalid !!!!! (bad)");
	        }
			
			//删除Signature元素部分-封内签名
			if(signatureType == XmlCipherUtil.SIGNATURETYPE_ENVELOPED) { 
				Node parent = sigElement.getParentNode();
				parent.removeChild(sigElement);
			} else if (signatureType == XmlCipherUtil.SIGNATURETYPE_ENVELOPING) {
				Node parentNode = sigElement.getParentNode();
				for(int i = 0; i < ObjectNodeList.getLength(); i++) {
					parentNode.appendChild(ObjectNodeList.item(i));
				}
				parentNode.removeChild(sigElement);
			}
			
			//删除Signature元素部分-封外签名
	        
	        /*
	         * 改造：规范中没有KeyInfo元素，不考虑KeyInfo部分的内容
	         */
//	        if (ki != null) {
//	           if (ki.containsX509Data()) {
//	              System.out.println("Could find a X509Data element in the KeyInfo");
//	           }
//
//	           X509Certificate cert = signature.getKeyInfo().getX509Certificate();
//
//	           if (cert != null) {
//	               /*
//	               System.out.println(
//	                  "I try to verify the signature using the X509 Certificate: "
//	                  + cert);
//	               */
//	        	   System.out.println("The XML signature in file "
//	                                  + f.toURL().toString() + " is "
//	                                  + (signature.checkSignatureValue(cert)
//	                                     ? "valid (good)"
//	                                     : "invalid !!!!! (bad)"));
//	           } 
//	           else {
//	               System.out.println("Did not find a Certificate");
//
//	               PublicKey pk = signature.getKeyInfo().getPublicKey();
//
//	               if (pk != null) {
//	            	   /*
//	                  	System.out.println(
//	                     "I try to verify the signature using the public key: "
//	                     + pk);
//	            	   */
//	            	   System.out.println("The XML signature in file "
//	                                     + f.toURL().toString() + " is "
//	                                     + (signature.checkSignatureValue(pk)
//	                                        ? "valid (good)"
//	                                        : "invalid !!!!! (bad)"));
//	               } else {
//	                  System.out.println(
//	                     "Did not find a public key, so I can't check the signature");
//	               }
//	           }
//	        } else {
//	            System.out.println("Did not find a KeyInfo");
//	        }
	    } catch (Exception ex) {
	         ex.printStackTrace();
	    }
	    
	    return result? 0 : -1;
	}

	@Override
	public long Decrypt(Document doc) {
		// TODO Auto-generated method stub
		log.trace("Decrypt - Begin");
		
		log.trace("Decrypt - Find Element 'EncryptedData' and doFinal");
		NodeList nl = doc.getElementsByTagName("xenc:EncryptedData");
		
		int count = 0;
		Document rst = null;
		for(int i = 0; i < nl.getLength(); i++) {
			
			Element element = (Element) nl.item(i);
			
			log.trace("Decrypt - Check Element 'KeyInfo' and Call XMLCipher init");
			Element KeyInfoElem = WSSecurityUtil.getDirectChildElement(element, "KeyInfo", WSSecurityContext.SIG_NS);
			String encryptType= KeyInfoElem.getAttribute("Type");
			
			if(encryptType.equals("LocalSymm")) { 
				rst = Decrypt_LocalSymm(doc, element);
			}
			else if(encryptType.equals("EnvelopSymm")) {
				rst = Decrypt_TransEnvelop(doc, element);
			}
			else if(encryptType.equals("TransSymm")) {
				rst = Decrypt_TransSymm(doc, element);
			}
		}
		
		log.debug("Decrypt Times : !!! - " + count + " time(s)");
		log.trace("Decrypt - End");
        try {
			String target = XmlCipherUtil.XMLtoStringWithCan(rst);
			log.debug("Decrypt - the plain txt is : \n" + target);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return 0;
	}

	public Document Decrypt_LocalSymm(Document doc, Element element) {
		
		log.trace("Decrypt - Call XMLCipher getInstance");
		
		XMLCipher xmlCipher = null;
		try {
			xmlCipher = XMLCipher.getInstance();
		} catch (XMLEncryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		Key_v810 key = new Key_v810();
		{
			Element KeyInfoElem = WSSecurityUtil.getDirectChildElement(element, "KeyInfo", WSSecurityContext.SIG_NS);
			
			Element KeyName = (Element) KeyInfoElem.getElementsByTagName("KeyName").item(0);
			String strKeyName = KeyName.getTextContent();
			
			Element IV = (Element) KeyInfoElem.getElementsByTagName("IV").item(0);
			String strIV = IV.getTextContent();
			
			key.setSrcDevice(strKeyName);
			key.setDstDevice(strKeyName);
			key.setIV(strIV);
		}
		
		try {
			xmlCipher.init(XMLCipher.DECRYPT_MODE, key);
		} catch (XMLEncryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		EncryptedData encryptedData = null;
		try {
			encryptedData = xmlCipher.loadEncryptedData(doc, element);
		} catch (XMLEncryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String alg = encryptedData.getEncryptionMethod().getAlgorithm();
		log.debug("Decrypt Algorithm : !!! - " + alg);
		//Assert.assertEquals(encryptedData.getEncryptionMethod().getAlgorithm(), 
		//					XMLCipher.MY_TESTCIPHER);
		
		try {
			return xmlCipher.doFinal(doc, element);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	public Document Decrypt_TransEnvelop(Document doc, Element element) {
		
//		Key secretKey = null;
//		try {
//			XMLCipher xmlCipher_keyWrap = XMLCipher.getInstance();
//			
//			//接收者的私钥
//			xmlCipher_keyWrap.init(Cipher.UNWRAP_MODE, null);
//			
//			EncryptedKey ek = xmlCipher_keyWrap.loadEncryptedKey(doc, element);
//			String encryptedKeyAlgorithm = ek.getEncryptionMethod().getAlgorithm();
//			
//			secretKey = xmlCipher_keyWrap.decryptKey(ek, encryptedKeyAlgorithm);
//
//		} catch (XMLEncryptionException e1) {
//			// TODO Auto-generated catch block
//			e1.printStackTrace();
//		}
		
		PublicKey_v810 pk = new PublicKey_v810();
		
		log.trace("Decrypt - Call XMLCipher getInstance");
			
		try {
			
			XMLCipher xmlCipher = XMLCipher.getInstance();
			
			xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
			xmlCipher.setKEK(pk);
		
			EncryptedData encryptedData = xmlCipher.loadEncryptedData(doc, element);
			String encryptedDataAlgorithm = encryptedData.getEncryptionMethod().getAlgorithm();
			log.debug("Decrypt Algorithm : !!! - " + encryptedDataAlgorithm);
			
			return xmlCipher.doFinal(doc, element);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	public Document Decrypt_TransSymm(Document doc, Element element) {
		
		log.trace("Decrypt - Call XMLCipher getInstance");
		
		XMLCipher xmlCipher = null;
		try {
			xmlCipher = XMLCipher.getInstance();
		} catch (XMLEncryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		Key_v810 key = new Key_v810();
		
		{
			Element KeyInfoElem = WSSecurityUtil.getDirectChildElement(element, "KeyInfo", WSSecurityContext.SIG_NS);
			
			Element SrcKeyName = (Element) KeyInfoElem.getElementsByTagName("SrcKeyName").item(0);
			String strSrcKeyName = SrcKeyName.getTextContent();
			
			Element DstKeyName = (Element) KeyInfoElem.getElementsByTagName("DstKeyName").item(0);
			String strDstKeyName = DstKeyName.getTextContent();
			
			Element IV = (Element) KeyInfoElem.getElementsByTagName("IV").item(0);
			String strIV = IV.getTextContent();
			
			key.setSrcDevice(strSrcKeyName);
			key.setDstDevice(strDstKeyName);
			key.setIV(strIV);
		}
		
		try {
			xmlCipher.init(XMLCipher.DECRYPT_MODE, key);
		} catch (XMLEncryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		EncryptedData encryptedData = null;
		try {
			encryptedData = xmlCipher.loadEncryptedData(doc, element);
		} catch (XMLEncryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String alg = encryptedData.getEncryptionMethod().getAlgorithm();
		log.debug("Decrypt Algorithm : !!! - " + alg);
		//Assert.assertEquals(encryptedData.getEncryptionMethod().getAlgorithm(), 
		//					XMLCipher.MY_TESTCIPHER);
		
		try {
			return xmlCipher.doFinal(doc, element);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	@Override
	public long SaveDecryptedFile(Document doc, String plainFileName) {
		try{
			TransformerFactory factory = TransformerFactory.newInstance();
			Transformer transformer = factory.newTransformer();
			
			DOMSource source = new DOMSource(doc);
			StreamResult result =  new StreamResult(new File(plainFileName));
			transformer.transform(source, result);
			
		}catch(TransformerException e){
			return -1;
		}
		return 0;
	}

}
