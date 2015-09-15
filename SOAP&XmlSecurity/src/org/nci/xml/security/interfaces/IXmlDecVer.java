package org.nci.xml.security.interfaces;

import org.w3c.dom.*;

public interface IXmlDecVer {

	public Document OpenXmlFile(String path);
	
	//public long DecryptAndVerify(Document doc);
	public long Verify(Document doc);
	public long Decrypt(Document doc);
	
	public long SaveDecryptedFile(Document doc, String plainFileName);
}
