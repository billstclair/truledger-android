package com.truledger.client;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMReader;
import org.spongycastle.openssl.PEMWriter;
import org.spongycastle.openssl.PasswordFinder;

public class Crypto {
	private static boolean isProviderInitialized = false;
	private static SecureRandom random;
	private static double ver;

    public Crypto() {
    	if (!isProviderInitialized) {
            Security.addProvider(new BouncyCastleProvider());
            random = new SecureRandom();
            double ver = Security.getProvider("SC").getVersion();
            setVer(ver);
            isProviderInitialized = true;
    	}
    }
    
    public KeyPair RSAGenerateKey(int keysize, BigInteger exponent) {
    	KeyPairGenerator kpg;
    	try {
    		kpg = KeyPairGenerator.getInstance("RSA");
    	} catch (NoSuchAlgorithmException e) {
    		return null;
    	}
    	AlgorithmParameterSpec spec = new RSAKeyGenParameterSpec(keysize, exponent);
    	try {
    		kpg.initialize(spec, random);
    	} catch (InvalidAlgorithmParameterException e) {
    		return null;
    	}
    	return kpg.genKeyPair();
    }
    
    final public static BigInteger defaultExponent = BigInteger.valueOf(65537);
    
    public KeyPair RSAGenerateKey(int keysize) {
    	return RSAGenerateKey(keysize, defaultExponent);
    }
    
	public KeyPair decodeRSAPrivateKey(String key, final String password) throws IOException {
	  Reader keyReader = new StringReader(key);
	  PasswordFinder pwd = new PasswordFinder() {
		  public char[] getPassword() {
			  return password.toCharArray();
		  }
	  };
	  PEMReader reader = new PEMReader(keyReader, pwd);
	  return (KeyPair)reader.readObject();
	}
	
	public String encodeRSAPrivateKey(KeyPair key, final String password) throws IOException {
		StringWriter keyWriter = new StringWriter();
		PEMWriter writer = new PEMWriter(keyWriter);
		writer.writeObject(key, "AES-256-CBC", password.toCharArray(), random);
		writer.flush();
		return keyWriter.getBuffer().toString();
	}
	
	public PublicKey decodeRSAPublicKey(String key) throws IOException {
		Reader keyReader = new StringReader(key);
		PEMReader reader = new PEMReader(keyReader);
		return (PublicKey)reader.readObject();
		}

	public PublicKey decodeRSAPublicKey(PublicKey key) {
		return key;
	}
	
	public String encodeRSAPublicKey(PublicKey key) throws IOException {
		StringWriter keyWriter = new StringWriter();
		PEMWriter writer = new PEMWriter(keyWriter);
		writer.writeObject(key);
		writer.flush();
		return keyWriter.getBuffer().toString();
	}
	
	public String encodeRSAPublicKey(KeyPair key) throws IOException {
		return encodeRSAPublicKey(key.getPublic());
	}
	
	public String sha1(byte[] buf) {
		return this.digest(buf, "SHA1");
	}
	
	public String sha1(String str) {
		return this.digest(str, "SHA1");
	}
	
	public String sha256(byte[] buf) {
		return this.digest(buf, "SHA256");
	}
	
	public String sha256(String str) {
		return this.digest(str, "SHA256");
	}
	
	public String digest(byte[] buf, String algorithm) {
		MessageDigest dig;
		try {
			dig = MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
		dig.update(buf);
		return Utility.bin2hex(dig.digest());
	}
	
	public String digest(String str, String algorithm) {
		return this.digest(str.getBytes(), algorithm);
	}
	
	String sign(String data, KeyPair key) {
		try {
			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initSign(key.getPrivate());
			sig.update(data.getBytes());
			byte[] signature = sig.sign();
			String res = Utility.base64Encode(signature);
			return res;
		} catch (Exception e) {
			System.out.println(e.toString());
			return null;
		}
	}

	public static double getVer() {
		return ver;
	}

	public static void setVer(double ver) {
		Crypto.ver = ver;
	}
}
