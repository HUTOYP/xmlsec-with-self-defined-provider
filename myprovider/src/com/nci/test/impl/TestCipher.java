package com.nci.test.impl;

import it.sauronsoftware.base64.Base64;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

public class TestCipher extends CipherSpi{

	private int m_mode;
	private Key m_key;
	private byte[] m_context;
	
	@Override
	protected byte[] engineDoFinal(byte[] arg0, int arg1, int arg2)
			throws IllegalBlockSizeException, BadPaddingException {
		// TODO Auto-generated method stub
		return implDoFinal(arg0);
	}

	@Override
	protected int engineDoFinal(byte[] arg0, int arg1, int arg2, byte[] arg3,
			int arg4) throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	//美国以外的国家应当实现此方法
	protected int engineGetBlockSize() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	protected byte[] engineGetIV() {
		// TODO Auto-generated method stub		
		byte[] IV = {};
		return IV;
	}

	@Override
	protected int engineGetOutputSize(int arg0) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	protected AlgorithmParameters engineGetParameters() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected void engineInit(int arg0, Key arg1, SecureRandom arg2)
			throws InvalidKeyException {
		// TODO Auto-generated method stub
		implInit(arg0, arg1);
	}

	@Override
	protected void engineInit(int arg0, Key arg1, AlgorithmParameterSpec arg2,
			SecureRandom arg3) throws InvalidKeyException,
			InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		implInit(arg0, arg1);
	}

	@Override
	protected void engineInit(int arg0, Key arg1, AlgorithmParameters arg2,
			SecureRandom arg3) throws InvalidKeyException,
			InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		implInit(arg0, arg1);
	}

	@Override
	protected void engineSetMode(String arg0) throws NoSuchAlgorithmException {
		// TODO Auto-generated method stub
		
	}

	@Override
	protected void engineSetPadding(String arg0) throws NoSuchPaddingException {
		// TODO Auto-generated method stub
		
	}

	@Override
	protected byte[] engineUpdate(byte[] arg0, int arg1, int arg2) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected int engineUpdate(byte[] arg0, int arg1, int arg2, byte[] arg3,
			int arg4) throws ShortBufferException {
		// TODO Auto-generated method stub
		return 0;
	}
	
	private void implInit(int mode, Key key)
	{
		this.m_mode = mode;  
        if (key instanceof SecretKeySpec) {  
            this.m_key = key;
        } else {  
            throw new RuntimeException("key invalid!");  
        } 
	}
	
	private byte[] implDoFinal(byte[] arg0) {  
        SecretKeySpec simpleKey = (SecretKeySpec) m_key;  
        if (m_mode == Cipher.ENCRYPT_MODE) {  
        	m_context = Base64.encode(arg0);
        } else if (m_mode == Cipher.DECRYPT_MODE) {  
        	m_context = Base64.decode(arg0);
        } else {  
            throw new RuntimeException("mode must be encrypt or decrypt!");  
        }  
        return m_context;  
    }  
}
