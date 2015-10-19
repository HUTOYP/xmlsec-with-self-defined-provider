package org.nci.soap.security.components;

import org.nci.soap.security.util.WSSecurityContext;

public class BinaryDigitalCert {
	
	//国际标准默认属性值 
	public static final String BASE64_ENCODING = WSSecurityContext.SOAPMESSAGE_NS + "#Base64Binary";
	public static final String X509V3_ValueType =  WSSecurityContext.X509TOKEN_NS + "#X509v3";
	
	public static final String BASE64_ENCODING_MLS = WSSecurityContext.SIG_NS + "base64";
	public static final String Cert_ValueType_MLS = WSSecurityContext.CERT_LEVEL_1;
	
	public String strValueType;
	public String strID;
	public String strEncodingType;
	
	public byte[] byteData;
	
	public BinaryDigitalCert(){
		this(Cert_ValueType_MLS, "", BASE64_ENCODING_MLS, null);
	}
	
	public BinaryDigitalCert(byte[] byteData) {
		this(Cert_ValueType_MLS, "", BASE64_ENCODING_MLS, byteData);
	}
	
	public BinaryDigitalCert(String strID, byte[] byteData) {
		this(Cert_ValueType_MLS, strID, BASE64_ENCODING_MLS, byteData);
	}
	
	public BinaryDigitalCert(String strValueType, String strID, String strEncodingType, byte[] byteData) {

		this.strValueType = strValueType;
		this.strID = strID;
		this.strEncodingType = strEncodingType;
		
		this.byteData = byteData;
	}

	public String getCertValueType() { return strValueType;}
	public void setCertValueType(String strValueType) { this.strValueType = strValueType; }

	public String getCertID() { return strID; }
	public void setCertID(String strID) { this.strID = strID; }

	public String getCertEncodingType() { return strEncodingType; }
	public void setCertEncodingType(String strEncodingType) { this.strEncodingType = strEncodingType; }

	public byte[] getByteData() { return byteData; }
	public void setByteData(byte[] byteData) { this.byteData = byteData; }
}
