package com.truledger.client;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

// The Android runtime contains a subset of some version of the Bouncy Castle crypto library
// Spongy Castle is a copy of Bouncy Castle, with the packages changed, so they don't collide
// with the Android runtime.
// https://github.com/rtyley/spongycastle
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMReader;
import org.spongycastle.openssl.PEMWriter;
import org.spongycastle.openssl.PasswordFinder;

public class Crypto {
	private static boolean isProviderInitialized = false;
	private static double ver;

    public Crypto() {
    	if (!isProviderInitialized) {
            Security.addProvider(new BouncyCastleProvider());
            double ver = Security.getProvider("SC").getVersion();
            setVer(ver);
            isProviderInitialized = true;
    	}
    }
    
	public KeyPair parsePrivateKey(String key, final String password) throws IOException {
	  Reader keyReader = new StringReader(key);
	  PasswordFinder pwd = new PasswordFinder() {
		  public char[] getPassword() {
			  return password.toCharArray();
		  }
	  };
	  PEMReader reader = new PEMReader(keyReader, pwd);
	  return (KeyPair)reader.readObject();
	}
	
	public String encodePrivateKey(KeyPair key, final String password) throws IOException {
		StringWriter keyWriter = new StringWriter();
		PEMWriter writer = new PEMWriter(keyWriter);
		SecureRandom random = new SecureRandom();
		writer.writeObject(key, "AES-256-CBC", password.toCharArray(), random);
		writer.flush();
		return keyWriter.getBuffer().toString();
	}
	
	public PublicKey parsePublicKey(String key) throws IOException {
		Reader keyReader = new StringReader(key);
		PEMReader reader = new PEMReader(keyReader);
		return (PublicKey)reader.readObject();
	}
	
	public String encodePublicKey(PublicKey key) throws IOException {
		StringWriter keyWriter = new StringWriter();
		PEMWriter writer = new PEMWriter(keyWriter);
		writer.writeObject(key);
		writer.flush();
		return keyWriter.getBuffer().toString();
	}
	
	public String encodePublicKey(KeyPair key) throws IOException {
		return encodePublicKey(key.getPublic());
	}

	public static double getVer() {
		return ver;
	}

	public static void setVer(double ver) {
		Crypto.ver = ver;
	}
}
