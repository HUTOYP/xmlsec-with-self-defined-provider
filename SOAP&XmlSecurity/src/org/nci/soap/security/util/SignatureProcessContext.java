package org.nci.soap.security.util;

public class SignatureProcessContext implements IProcessContext{
	
	@Override
	public int getProcessContextType() {
		// TODO Auto-generated method stub
		return 1;	//签名
	}
	
	//Attribute id in Element <Signature>
	private String id;
	
	//Element<BinarySecurityToken> URI in Signature
	private String uri;
	
	//secret level
	private int level;
	
	public SignatureProcessContext(String strid, String struri, int nlevel) {
		
		id = strid;
		uri = struri;
		
		level = nlevel;
	}
	
	public String getSignatureID(){ return id; }
	public String getSignatureBSTID(){ return uri; }
	
	@Override
	public int getProcessLevel() {
		// TODO Auto-generated method stub
		return level;
	}
}
