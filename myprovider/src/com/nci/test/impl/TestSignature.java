package com.nci.test.impl;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

public class TestSignature extends SignatureSpi{

	PublicKey m_publicKey;
	PrivateKey m_privateKey;
	
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
		
	}

	@Override
	protected byte[] engineSign() throws SignatureException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
		// TODO Auto-generated method stub
		return false;
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
