xmlsec-with-self-defined-provider
=================================

xmlsec with self-defined provider (using java, based on xmlsec-opensource)

1、Supports SOAP message encryption function. 提供SOAP消息加密功能（基于WS-Security）  
2、Supports a variety of ways XMLSEC encryption. 提供多种方式的XMLSEC加密功能  
3、Provides a test CSP. 提供模拟的CSP（Cipher Service Provider）  

Java Cryptography Architecture (JCA) Reference Guide：  
http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html  
Java Cryptography Extension (JCE) Reference Guide：  
http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html  
Java Cryptography Architecture Standard Algorithm Name Documentation：  
http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html  

目录说明：  
jce: 屏蔽SUN公司对CSP签名验证的强制检查（jce工程来自于openJdk1.6）  
myprovider: 用于测试的密码服务提供者实现  
