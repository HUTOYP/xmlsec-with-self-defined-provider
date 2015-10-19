package org.nci.xml.security.contexts;

//XML元素加密上下文接口
public class ElementEncContext {

	/**
	 * 加密方式
	 * true	-代表对元素内容加密
	 * false-代表对元素加密
	 */
	public boolean contentMode;
	/**
	 * EncryptedData元素的id属性值
	 * 如果为空则不需要显示该属性，或者由程序自动产生。
	 */
	public String id;
	/**
	 * EncryptedData元素的Encoding属性值
	 * 如果为空则不需要显示该属性，默认以BASE64编码。
	 * 【WARN】不支持用户自定义该属性值 20150313 by snail
	 */
	public String encoding;
	/**
	 * 是否需要对密钥加密
	 * 即生成EncryptedKey元素。
	 * 【WARN】未实现 20150313 by snail
	 */
	public boolean keyWrapped;
	
	public ElementEncContext(boolean contentMode){
		CreateElementEncContext(contentMode, "", "", false);
	}
	
	public ElementEncContext(boolean contentMode, String id){
		CreateElementEncContext(contentMode, id, "", false);
	}
	
	public ElementEncContext(boolean contentMode, String id, String encoding, boolean keyWrapped){
		CreateElementEncContext(contentMode, id, encoding, keyWrapped);
	}
	
	public void CreateElementEncContext(boolean contentMode, String id, String encoding, boolean keyWrapped){
		
		this.contentMode = contentMode;
		this.id = id;
		this.encoding = encoding;
		this.keyWrapped = keyWrapped;
	}
}
