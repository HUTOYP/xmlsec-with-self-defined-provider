package org.nci.soap.security.components;

import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class RecentCreateTimeCache {
	private static RecentCreateTimeCache m_instance = null;

    //private long time_to_live = 10*1000*60; 
    private Date m_recentDate = new Date(); 
    private Log log = LogFactory.getLog(this.getClass()); 

    private RecentCreateTimeCache()
    {

    }
    
    public static synchronized RecentCreateTimeCache getInstance()
    {
        if ( m_instance == null )
        {
            m_instance = new RecentCreateTimeCache(); 
        }
        return(m_instance); 
    }

    public boolean refreshRecentDate(Date date)
    {
        log.debug("Attempting to refresh the recent time to the cache"); 
        long recentDate = m_recentDate.getTime();
        long newDate = date.getTime();
        
        if ( newDate > recentDate )		//Replay Attack
        {
            log.debug("The message REPLAY!!!"); 
            return false;
        }
        else
        {
            m_recentDate = date;
            return true;
        }
    }
}
