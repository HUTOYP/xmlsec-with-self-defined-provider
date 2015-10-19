package org.nci.soap.security.components;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;

import org.apache.ws.security.util.WSSecurityUtil;
import org.nci.soap.security.util.WSSecurityContext;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class TimestampCreator {
	/**
	 * Add Element TimeStamp For Security
	 * @return Element TimeStamp
	 */
	
	private boolean m_isNeedLifeTime = false;
	public void setIsNeedTimetoLife(boolean need) {
		m_isNeedLifeTime = need;
	}
	
	private int m_lifeTime = 60 * 10;
	public void setLifeTime(int time){
		m_lifeTime = time;
	}

	String createTime;
	
	public Element setTimeStampElem(Document doc){
		
		Element elementTime = doc.createElementNS(WSSecurityContext.WSU_NS, "wsu:Timestamp");
		
		if(doc.lookupNamespaceURI(WSSecurityContext.WSU_PREFIX) == null){
			WSSecurityUtil.setNamespace(elementTime, WSSecurityContext.WSU_NS, WSSecurityContext.WSU_PREFIX);
		}
		
		//Create
    	SimpleDateFormat zulu = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
    	zulu.setTimeZone(TimeZone.getTimeZone("GMT"));
    	Calendar rightNow = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
    	this.createTime = zulu.format(rightNow.getTime());
    	
    	Element elementCreated =
    			doc.createElementNS(
    					WSSecurityContext.WSU_NS,
    					WSSecurityContext.WSU_PREFIX + ":" + WSSecurityContext.CREATED_LN);
    	elementCreated.appendChild(doc.createTextNode(zulu.format(rightNow.getTime())));
    	elementTime.appendChild(elementCreated);
    	
    	//Expires
    	if(m_isNeedLifeTime){
    		Element elementExpires = 
    				doc.createElementNS(WSSecurityContext.WSU_NS, 
    						WSSecurityContext.WSU_PREFIX + ":" + WSSecurityContext.EXPIRES_LN);
    		rightNow.add(Calendar.SECOND, m_lifeTime);
    		elementExpires.appendChild(doc.createTextNode(zulu.format(rightNow.getTime())));
    		
    		elementTime.appendChild(elementExpires);
    	}
    	return elementTime;
	}
	
	public String GetCreateTime() {
		
		return createTime;
	}
}
