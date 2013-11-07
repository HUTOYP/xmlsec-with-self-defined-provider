package com.nci.provider;

import java.security.Provider;
import java.security.AccessController;

public class TestProvider extends Provider{

	public static String info = "JCE Test Provider v1.0";
	
	public TestProvider()
	{
		super("TestProvider", 1.0, info);
	
		AccessController.doPrivileged(new java.security.PrivilegedAction<Object> (){
			public Object run(){
				
				put("Cipher.TestCipher", "com.nci.test.impl.TestCipher");
				
				put("Signature.TestSignature", "com.nci.test.impl.TestSignature");
		
				return null;
			}
		});
	}
}
