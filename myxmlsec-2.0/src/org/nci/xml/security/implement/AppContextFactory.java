package org.nci.xml.security.implement;

import org.nci.xml.security.contexts.IXmlAppContext;
import org.nci.xml.security.contexts.LocalSymmContext;
import org.nci.xml.security.contexts.TransEnvelopContext;
import org.nci.xml.security.contexts.TransSymmContext;

public class AppContextFactory {
	
	public static IXmlAppContext  createLocalSymmContext(int opID){
		
		IXmlAppContext context = new LocalSymmContext(opID);
		
		return context;
	}
	
	public static IXmlAppContext  createTransEnvelopContext(int opID, byte[]  peerCert){
		
		IXmlAppContext context = new TransEnvelopContext(opID, peerCert);
		
		return context;
	}
	
	public static IXmlAppContext  createTransSymmContext(int opID, String peerDevID){
		
		IXmlAppContext context = new TransSymmContext(opID, peerDevID);
		
		return context;
	}
}
