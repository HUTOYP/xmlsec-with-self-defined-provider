package jceprovidertest;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class ProviderTest {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		testCipher();
			
		testSignature();
	}
	
	public static void testCipher()
	{
		Provider p = Security.getProvider("TestProvider");
		
		System.out.println("My provider name is " + p.getName());
		System.out.println("My provider version is " + p.getVersion());
		System.out.println("My provider info is " + p.getInfo());
	
		
		byte[] bits128 = {
	            (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
	            (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
	            (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
	            (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
		
		byte[] input = {
	            (byte) 0xF0, (byte) 0xF1, (byte) 0xF2, (byte) 0xF3,
	            (byte) 0xF4, (byte) 0xF5, (byte) 0xF6, (byte) 0xF7,
	            (byte) 0xF8, (byte) 0xF9, (byte) 0xFA, (byte) 0xFB,
	            (byte) 0xFC, (byte) 0xFD, (byte) 0xFE, (byte) 0xFF};
	    
		Key key = new SecretKeySpec(bits128, "TestKey");
		
		try {
			Cipher c = Cipher.getInstance("TestCipher", p.getName());
			System.out.println("My cipher algorithm name is " + c.getAlgorithm());
			
			c.init(Cipher.ENCRYPT_MODE, key);
			byte[] output = c.doFinal(input);
			
			System.out.println("output:\n" + Arrays.toString(output));
			
			c.init(Cipher.DECRYPT_MODE, key);
			byte[] output_plain = c.doFinal(output);
			
			System.out.println("output plain:\n" + Arrays.toString(output_plain));
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static void testSignature()
	{
		Provider p = Security.getProvider("TestProvider");
		
		System.out.println("My provider name is " + p.getName());
		System.out.println("My provider version is " + p.getVersion());
		System.out.println("My provider info is " + p.getInfo());
	
		byte[] input = {
	            (byte) 0xF0, (byte) 0xF1, (byte) 0xF2, (byte) 0xF3,
	            (byte) 0xF4, (byte) 0xF5, (byte) 0xF6, (byte) 0xF7,
	            (byte) 0xF8, (byte) 0xF9, (byte) 0xFA, (byte) 0xFB,
	            (byte) 0xFC, (byte) 0xFD, (byte) 0xFE, (byte) 0xFF};
	    		
		try {
			Signature s = Signature.getInstance("TestSignature", p.getName());
			System.out.println("My signature algorithm name is " + s.getAlgorithm());
			
			s.initSign(null);
			s.update(input);
			
			byte[] output = s.sign();
			System.out.println("output:\n" + Arrays.toString(output));
			
			Signature v = Signature.getInstance("TestSignature", p.getName());
			v.initVerify((PublicKey)null);
			v.update(input);
			boolean result = v.verify(output);
			
			if(result == true)
				System.out.println("Verify result:\nverify success!");
			else
				System.out.println("Verify result:\nverify failure!");
				
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchProviderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
