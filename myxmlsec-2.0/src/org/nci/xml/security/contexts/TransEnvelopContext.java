package org.nci.xml.security.contexts;

//XML加密上下文实现-数字信封加密方式
public class TransEnvelopContext implements IXmlAppContext{

	private int m_operateid;
	private byte[] m_peerCert;		//对端数字证书
	
	public TransEnvelopContext(int opid, byte[] peerCert){
		
		m_operateid = opid;
		m_peerCert = peerCert;
	}
	
	@Override
	public int getOperateID() {
		// TODO Auto-generated method stub
		return m_operateid;
	}
	@Override
	public void setOperateID(int opid) {
		// TODO Auto-generated method stub
		m_operateid = opid;
	}

	//对端数字证书
	public byte[] getPeerCert() {
		return m_peerCert;
	}
	public void setPeerCert(byte[] peerCert) {
		m_peerCert = peerCert;
	}
}
