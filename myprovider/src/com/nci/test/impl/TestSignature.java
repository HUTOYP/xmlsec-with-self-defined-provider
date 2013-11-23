package com.nci.test.impl;

import it.sauronsoftware.base64.Base64;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

public class TestSignature extends SignatureSpi{

	PublicKey m_publicKey;
	PrivateKey m_privateKey;
	
	byte[] m_signdata;
	int m_signdata_len;
	
	@Override
	protected void engineInitVerify(PublicKey publicKey)
			throws InvalidKeyException {
		// TODO Auto-generated method stub
		m_publicKey = publicKey;
	}

	@Override
	protected void engineInitSign(PrivateKey privateKey)
			throws InvalidKeyException {
		// TODO Auto-generated method stub
		m_privateKey = privateKey;
	}

	@Override
	protected void engineUpdate(byte b) throws SignatureException {
		// TODO Auto-generated method stub
		
	}

	@Override
	protected void engineUpdate(byte[] b, int off, int len)
			throws SignatureException {
		// TODO Auto-generated method stub
		m_signdata = new byte[len];
		
		for(int i = 0; i < len; i++){
			m_signdata[i] = b[ off + i ];
		}
		
		m_signdata_len = len;
	}

	protected void engineSign(byte[] b)
			throws SignatureException {
	
		m_signdata = b;
		m_signdata_len = b.length;
	}
	
	@Override
	protected byte[] engineSign() throws SignatureException {
		// TODO Auto-generated method stub
		byte[] signeddata = Base64.encode(m_signdata);
		return signeddata;
	}

	@Override
	protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
		// TODO Auto-generated method stub		
		byte[] signeddata = engineSign();
		
		if(signeddata.length != sigBytes.length)
			return false;
		
		for(int i = 0; i < signeddata.length; i++)
		{
			if(signeddata[i] != sigBytes[i])
				return false;
		}
		return true;
	}

	@Override
	protected void engineSetParameter(String param, Object value)
			throws InvalidParameterException {
		// TODO Auto-generated method stub
		
	}

	@Override
	protected Object engineGetParameter(String param)
			throws InvalidParameterException {
		// TODO Auto-generated method stub
		return null;
	}
}
