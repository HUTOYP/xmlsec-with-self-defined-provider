package org.apache.xml.security.algorithms.implementations;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithmSpi;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.Base64;

public class SignatureTest extends SignatureAlgorithmSpi{

	private java.security.Signature _signatureAlgorithm = null;
	
    public String engineGetURI()
    {
    	JCEMapper.setProviderId("TestProvider");
    	return XMLSignature.ALGO_ID_SIGNATURE_TEST;
    }
	
	public SignatureTest() throws XMLSignatureException
	{	
		String algorithmID = JCEMapper.translateURItoJCEID(this.engineGetURI());
		
		String provider = JCEMapper.getProviderId();
		try {
		    if (provider==null) {
			this._signatureAlgorithm = Signature.getInstance(algorithmID);
		    } else {
	      	 	this._signatureAlgorithm = Signature.getInstance(algorithmID,provider);
		    }
		} catch (java.security.NoSuchAlgorithmException ex) {
		    Object[] exArgs = { algorithmID, ex.getLocalizedMessage() };

		    throw new XMLSignatureException("algorithms.NoSuchAlgorithm", exArgs);
		} catch (NoSuchProviderException ex) {
		    Object[] exArgs = { algorithmID, ex.getLocalizedMessage() };

		    throw new XMLSignatureException("algorithms.NoSuchAlgorithm", exArgs);
		}
	}
	
	@Override
	protected String engineGetJCEAlgorithmString() {
		// TODO Auto-generated method stub
		return this._signatureAlgorithm.getAlgorithm();
	}

	@Override
	protected String engineGetJCEProviderName() {
		// TODO Auto-generated method stub
		return this._signatureAlgorithm.getProvider().getName();
	}

	@Override
	protected void engineUpdate(byte[] input) throws XMLSignatureException {
		// TODO Auto-generated method stub
		try {
		    this._signatureAlgorithm.update(input);
		} catch (SignatureException ex) {
		    throw new XMLSignatureException("empty", ex);
		}
	}

	@Override
	protected void engineUpdate(byte input) throws XMLSignatureException {
		// TODO Auto-generated method stub
		
	}

	@Override
	protected void engineUpdate(byte[] buf, int offset, int len)
			throws XMLSignatureException {
		// TODO Auto-generated method stub
		try {
            this._signatureAlgorithm.update(buf, offset, len);
        } catch (SignatureException ex) {
            throw new XMLSignatureException("empty", ex);
        }
	}

	@Override
	protected void engineInitSign(Key signingKey) throws XMLSignatureException {
		// TODO Auto-generated method stub
		try {
			this._signatureAlgorithm.initSign((PrivateKey) signingKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	protected void engineInitSign(Key signingKey, SecureRandom secureRandom)
			throws XMLSignatureException {
		// TODO Auto-generated method stub
		try {
			this._signatureAlgorithm.initSign((PrivateKey) signingKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	protected void engineInitSign(Key signingKey,
			AlgorithmParameterSpec algorithmParameterSpec)
			throws XMLSignatureException {
		// TODO Auto-generated method stub
		try {
			this._signatureAlgorithm.initSign((PrivateKey) signingKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	protected byte[] engineSign() throws XMLSignatureException {
		// TODO Auto-generated method stub
		try {
            byte jcebytes[] = this._signatureAlgorithm.sign();
            return jcebytes;
        } catch (SignatureException ex) {
            throw new XMLSignatureException("empty", ex);
        }
	}

	@Override
	protected void engineInitVerify(Key verificationKey)
			throws XMLSignatureException {
		// TODO Auto-generated method stub
		try {
			this._signatureAlgorithm.initVerify((PublicKey) verificationKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	protected boolean engineVerify(byte[] signature)
			throws XMLSignatureException {
		// TODO Auto-generated method stub
		try { 
            return this._signatureAlgorithm.verify(signature);
        } catch (SignatureException ex) {
            throw new XMLSignatureException("empty", ex);
        }
	}

	@Override
	protected void engineSetParameter(AlgorithmParameterSpec params)
			throws XMLSignatureException {
		// TODO Auto-generated method stub
		
	}

	@Override
	protected void engineSetHMACOutputLength(int HMACOutputLength)
			throws XMLSignatureException {
		// TODO Auto-generated method stub
		
	}
}