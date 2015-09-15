package org.nci.soap.security.components;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import org.apache.ws.security.util.WSSecurityUtil;
import org.nci.soap.security.exception.WSAccessException;
import org.nci.soap.security.util.WSSecurityContext;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class TimestampValidator {
	private long ttl = 60*10*1000; 

    /* Different Types of Time Formats! */
    private String[] zuluformats = {  
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.S'Z'", 
        "yyyy-MM-dd'T'HH:mm:ss Z", 
        "yyyy-MM-dd'T'HH:mm:ss.S Z"
    };

    public void setAcceptedDelta(long delta)
    {
        ttl = delta; 
    }
    
    String createTime;
    
    /**
     * This method validates the Timestamp according the NCES Security Architecture 0.3 spec.
     * If the timestamp expires, this is not valid. This is why there is a timetolive that is
     * enforced. 
     * 
     * @param env the SOAP envelope
    * @throws a WSAccessException 
    */
    public boolean validate(Element timestampElem) throws WSAccessException
    {
		try
		{
			if(timestampElem != null)
			{
				//Find TimeStamp node.. 
				//log.debug("Finding the timestamp node."); 
				//Node tstmpNode = WSSecurityUtil.findElement(timestampElem, ContextFor15.TIMESTAMP_TOKEN_LN, ContextFor15.WSU_NS);
				Node tstmpNode = (Node)timestampElem;
				
				//log.debug("Looking for the Created Node"); 
				Node cre = WSSecurityUtil.findElement(tstmpNode, WSSecurityContext.CREATED_LN, WSSecurityContext.WSU_NS);
				Node exp = WSSecurityUtil.findElement(tstmpNode, WSSecurityContext.EXPIRES_LN, WSSecurityContext.WSU_NS);
				
				//if( exp != null )
				//{
				//	String expString = exp.getTextContent();
				//	setAcceptedDelta(Long.parseLong(expString));
				//}
		
				//Add By HUJQ For MultiSecretProj, 20120726 
				if(exp != null && cre != null){
					
					String creString = cre.getTextContent();
					this.createTime = creString;
					
					Date createdDate = null; 
		
					for ( int i = 0; i < zuluformats.length && createdDate == null; i++ )
					{
						try
						{
						    //log.debug("Trying zulu format # " + i + "which is " + zuluformats[i]); 
							SimpleDateFormat zulu = new SimpleDateFormat(zuluformats[i]);
							zulu.setTimeZone(TimeZone.getTimeZone("GMT"));
							//log.debug("Attempting to parse " + creString); 
							createdDate = zulu.parse(creString); 
							//log.debug("Successfully parsed created date = " + createdDate); 
						}
						catch ( ParseException p )
						{
							if ( i == (zuluformats.length - 1) )
							{
								//log.fatal("We could not parse the timestamp: " + creString); 
								throw new WSAccessException(
		                           new String(WSAccessException.TIMESTAMP_UNPARSEABLE + ":" + creString));
							}
						}
					}
		
					String expString = exp.getTextContent();
					Date expireDate = null;
		
					for ( int i = 0; i < zuluformats.length && expireDate == null; i++ )
					{
						try
						{
							//log.debug("Trying zulu format # " + i + "which is " + zuluformats[i]); 
							SimpleDateFormat zulu = new SimpleDateFormat(zuluformats[i]);
							zulu.setTimeZone(TimeZone.getTimeZone("GMT"));
							//log.debug("Attempting to parse " + expireDate); 
							expireDate = zulu.parse(expString); 
							//log.debug("Successfully parsed created date = " + expireDate); 
						}
						catch ( ParseException p )
						{
							if ( i == (zuluformats.length - 1) )
							{
								//log.fatal("We could not parse the timestamp: " + expString); 
								throw new WSAccessException(
		                           new String(WSAccessException.TIMESTAMP_UNPARSEABLE + ":" + expString));
							}
						}
					}
		
					boolean ret = RecentCreateTimeCache.getInstance().refreshRecentDate(createdDate);
					if(ret == false)	return false;
					
					long rightNow = Calendar.getInstance().getTime().getTime();
					long created = createdDate.getTime();
					long expire = expireDate.getTime();
					
					String except = null;
					if(rightNow > expire)
						except = WSAccessException.TIMESTAMP_EXPIRED;
					else if(created > rightNow)
						except = WSAccessException.CRAZY_FUTURE_TIMESTAMP;
					else if( created > expire)
						except = WSAccessException.CRAZY_FUTURE_TIMESTAMP;
					
					if ( except != null )
					{
					    System.out.print("Timestamp Exception(BOTH CREATED AND EXPIRED): TIMESTAMP_EXPIRED OR CRAZY_FUTURE_TIMESTAMP"); 
					    //WSAccessException wae = new WSAccessException(except);
					    //throw (wae); 
					    return false;
					}
					return true;
				}
				else if(exp != null && cre == null){
					
					String expString = exp.getTextContent();
					Date expireDate = null;
			
					for ( int i = 0; i < zuluformats.length && expireDate == null; i++ )
					{
						try
						{
							//log.debug("Trying zulu format # " + i + "which is " + zuluformats[i]); 
							SimpleDateFormat zulu = new SimpleDateFormat(zuluformats[i]);
							zulu.setTimeZone(TimeZone.getTimeZone("GMT"));
							//log.debug("Attempting to parse " + expireDate); 
							expireDate = zulu.parse(expString); 
							//log.debug("Successfully parsed created date = " + expireDate); 
						}
						catch ( ParseException p )
						{
							if ( i == (zuluformats.length - 1) )
							{
								//log.fatal("We could not parse the timestamp: " + expString); 
								throw new WSAccessException(
										new String(WSAccessException.TIMESTAMP_UNPARSEABLE + ":" + expString));
							}
						}
					}
		
					long rightNow = Calendar.getInstance().getTime().getTime();
					long expire = expireDate.getTime();
		
					String except = null;
					if(rightNow > expire)
						except = WSAccessException.TIMESTAMP_EXPIRED;
					if ( except != null )
					{
						System.out.println("Timestamp Exception(ONLY EXPIRED): TIMESTAMP_EXPIRED"); 
						//WSAccessException wae = new WSAccessException(except);
						//throw (wae); 
						return false;
					}
					
					return true;
				}
				//****************************************************************************************
				else if ( exp == null && cre != null )
				{
					/* todo - take out newlines */
					String creString = cre.getTextContent();
					this.createTime = creString;
					
					Date createdDate = null; 
					
					for ( int i = 0; i < zuluformats.length && createdDate == null; i++ )
					{
					    try 
					    {
					    	//log.debug("Trying zulu format # " + i + "which is " + zuluformats[i]); 
							SimpleDateFormat zulu = new SimpleDateFormat(zuluformats[i]);
							zulu.setTimeZone(TimeZone.getTimeZone("GMT"));
							//log.debug("Attempting to parse " + creString); 
							createdDate = zulu.parse(creString); 
							//log.debug("Successfully parsed created date = " + createdDate); 
					    }
					    catch ( ParseException p )
					    {
					    	if ( i == (zuluformats.length - 1) )
					    	{
					    		//log.fatal("We could not parse the timestamp: " + creString); 
					    		throw new WSAccessException(
		                           new String(WSAccessException.TIMESTAMP_UNPARSEABLE + ":" + creString));
					    	}
					    }
					}
		
					boolean ret = RecentCreateTimeCache.getInstance().refreshRecentDate(createdDate);
					if(ret == false)	return false;
		
					long rightNow = Calendar.getInstance().getTime().getTime();
					long created = createdDate.getTime();
		
					//log.debug("RightNow = " + Calendar.getInstance().getTime());
					//log.debug("CreatedDate = " +  createdDate); 
					String except = null;
		
					if ( rightNow - created > ttl )
						except = WSAccessException.TIMESTAMP_EXPIRED;
					else if ( created > rightNow + ttl )
						except = WSAccessException.CRAZY_FUTURE_TIMESTAMP;
		
					if ( except != null )
					{
						System.out.println("Timestamp Exception(ONLY CREATED): TIMESTAMP_EXPIRED OR CREAY_FUTURE_TIMESTAMP"); 
						//WSAccessException wae = new WSAccessException(except);
						//throw (wae); 
						return false;
					}
					return true;
				}
				else
				{
					System.out.println("No timestamp!"); 
					//throw new WSAccessException(WSAccessException.NO_TIMESTAMP);
					return false;
				}		
			}
			else
			{
				System.out.println("No timestamp!"); 
				//throw new WSAccessException(WSAccessException.NO_TIMESTAMP);
				return false;
			}
		}
		catch ( Exception e )
		{
		    System.out.println("Throwing exception " + e.getStackTrace()); 
		    //throw new WSAccessException (e); 
		    return false;
		}
    }
    
	public String GetCreateTime() {
		
		return createTime;
	}
}
