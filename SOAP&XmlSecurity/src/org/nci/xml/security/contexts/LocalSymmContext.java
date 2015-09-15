package org.nci.xml.security.contexts;

//XML加密上下文实现-本地存储加密方式
public class LocalSymmContext implements IXmlAppContext{

	int m_operateid;
	
	public LocalSymmContext(int opid){
		
		m_operateid = opid;
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
}
