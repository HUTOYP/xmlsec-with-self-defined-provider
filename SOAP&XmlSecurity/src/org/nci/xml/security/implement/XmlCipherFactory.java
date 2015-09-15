package org.nci.xml.security.implement;

import org.nci.xml.security.contexts.IXmlAppContext;
import org.nci.xml.security.interfaces.*;

public class XmlCipherFactory {

	public static IXmlEncSign CreateEncSig(IXmlAppContext context)
	{
		IXmlEncSign encSign = new XmlEncSign(context);
		return encSign;
	}
		
	public static IXmlDecVer CreateDecVer()
	{
		IXmlDecVer decVer = new XmlDecVer();
		return decVer;
	}
}
