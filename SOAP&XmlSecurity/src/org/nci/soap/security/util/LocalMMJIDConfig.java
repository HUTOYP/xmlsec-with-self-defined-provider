package org.nci.soap.security.util;

import org.nci.xml.security.util.XmlCipherUtil;

/**
 * This class 保证在程序运行的过程中仅需获取一次本地密码机标识
 * @author snail
 */
public class LocalMMJIDConfig {
	
	private String strLocalMMJID;
	
	private static LocalMMJIDConfig m_instance = null;
	public static LocalMMJIDConfig GetInstance() {
		if(m_instance == null)
			m_instance = new LocalMMJIDConfig();
		return m_instance;
	}

	private LocalMMJIDConfig() {
		strLocalMMJID = "";
	}
	
	public String GetLocalMMJID() {
		
		if(strLocalMMJID == "") {
		
			System.out.println("调用底层接口获取本地密码机标识");
			strLocalMMJID =  XmlCipherUtil.GetLocalMMID();
		}
		
		return strLocalMMJID;
	}
}
