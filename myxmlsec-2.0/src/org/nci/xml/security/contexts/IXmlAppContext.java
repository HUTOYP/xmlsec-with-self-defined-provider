package org.nci.xml.security.contexts;

//XML加密上下文接口
public interface IXmlAppContext {

	//共有属性：操作ID，【暂且不用】 20150313 by snail
	public int getOperateID();
	public void setOperateID(int opid);
}
