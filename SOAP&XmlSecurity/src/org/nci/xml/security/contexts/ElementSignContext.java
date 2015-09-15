package org.nci.xml.security.contexts;

//XML元素签名上下文接口
public class ElementSignContext {
	
	/**
	 * 元素Signature的ID属性值
	 * 默认为空，不显示该属性
	 */
	public String id;
	
	/**
	 * 数字签名格式
	 * 封内(Enveloped)-	1;
	 * 封外(Enveloping)-	2;
	 */
	public int signType;
}
