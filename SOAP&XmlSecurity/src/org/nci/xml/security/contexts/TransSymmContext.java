package org.nci.xml.security.contexts;

//XML加密上下文实现-端端传输加密方式
public class TransSymmContext implements IXmlAppContext{

	private int m_operateid;
	private String m_peerDevid;		//对端密码机标识
	
	public TransSymmContext(int opid, String peerDevID){
		
		m_operateid = opid;
		m_peerDevid = peerDevID;
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

	//对端密码机标识
	public String getPeerDevid() {
		return m_peerDevid;
	}
	public void setPeerDevid(String peerDevID) {
		this.m_peerDevid = peerDevID;
	}
}
