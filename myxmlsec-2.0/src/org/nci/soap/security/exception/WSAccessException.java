package org.nci.soap.security.exception;

public class WSAccessException extends Exception
{
	/**
	 * Default SerialVersionUID
	 */
	private static final long serialVersionUID = 1L;
	
	public static final String ROLE_EXCEPTION = "The user did not have the authorized role to access this web service."; 
	public static final String NO_SECURITY_HEADER ="The SOAP header did not have a WS-Security Header in it.";
	public static final String TIMESTAMP_EXPIRED = "The WS-Security Timestamp Has Expired!";
	public static final String NO_TIMESTAMP="The WS-Security message did not have a timestamp, as is required.";
	public static final String NO_TIMESTAMP_EXPIRE="The WS-Security Timestamp Had No Expiration, as is required.";
	public static final String CRAZY_FUTURE_TIMESTAMP="The WS-Security Timestamp Creation Time was too far in the future.";
	public static final String TIMESTAMP_UNPARSEABLE="Problems were encountered parsing the Timestamp of the message.";
	public static final String NO_MESSAGE="There was no Message sent to the Axis Handler Framework"; 
	
	public static final String NO_MSGID = "There was no WS-Addressing MessageID in the SOAP Header"; 
	public static final String MSGID_REPLAY="The Message ID in the WS-Addressing Header has been Replayed.";
	public static final String LABEL_ENFORCEMENT="The subject's security label was insufficient for access."; 
	public static final String NO_IDENTITY="No identity was passed to the client handler."; 
	
	public static final String NO_CRYPTO="No crypto module loaded. The system may not have been able to load the properties." +
													"Check error logs for details."; 
	
	public static final String NO_SOAPHEADER = "The SOAP Message did not have a SOAP Header in it.";

	public WSAccessException() {

    }
	public WSAccessException(String msg) {
        super(msg);
    }
	
	public WSAccessException(Throwable cause) {
        super(cause);
    }
	
	public WSAccessException(String msg, Throwable cause) {
        super(msg, cause); 
    }
}
