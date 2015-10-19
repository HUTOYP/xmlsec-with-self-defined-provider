package org.nci.soap.security.util;

public class EncryptProcessContext implements IProcessContext{

	@Override
	public int getProcessContextType() {
		// TODO Auto-generated method stub
		return 0;	//加密
	}
	
	//内容加密标志，若为true，表示内容加密
	private boolean contentFlag;
	//加密元素ID
	private String encryptID;
	//加密密级信息
	private int level;
		
	public EncryptProcessContext(boolean contentflag, String strid, int nlevel){
		
		contentFlag = contentflag;
		encryptID = strid;
		level = nlevel;
	}
	
	public boolean getContentFlag(){ return contentFlag; }
	public String getEncryptedID(){ return encryptID; }

	@Override
	public int getProcessLevel() {
		// TODO Auto-generated method stub
		return level;
	}

	private boolean needEncoding;
	private String encoding;
	public void setEncoding(String encoding){ 
		needEncoding = true;
		this.encoding = encoding; 
	}
	public boolean judgeNeedEncoding(){ return needEncoding; }
	public String getEncoding(){ return encoding; }
	
	private boolean needMimeType;
	private String mimeType;
	public void setMimeType(String mimeType){ 
		needMimeType = true;
		this.mimeType = mimeType; 
	}
	public boolean judgeNeedMimeType(){ return needMimeType; }
	public String getMimeType(){ return mimeType; }
}
