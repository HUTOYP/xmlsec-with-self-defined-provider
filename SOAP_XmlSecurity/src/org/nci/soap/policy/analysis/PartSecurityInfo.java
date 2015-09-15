package org.nci.soap.policy.analysis;

import org.w3c.dom.Node;

public class PartSecurityInfo {
	
	public int SecretLevel; 
	
	public String EncryptingNodeID;		//待加密元素ID-用以签名时明文元素索引
	public Node EncryptingNode;			//待加密元素-明文
	
	public String EncryptedNodeID;		//加密后元素ID-用以加密后密文元素索引
	public Node EncryptedNode;			//加密后元素-密文
	
	public boolean ContentFlag;			//false：对元素加密；true：对内容加密
		
	public PartSecurityInfo(){
		
		SecretLevel = 0;
		
		EncryptingNodeID = "";
		EncryptingNode = null;
		
		EncryptedNodeID = "";
		EncryptedNode = null;
		
		ContentFlag = true;
	}
}
