package com.truledger.client;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;

import android.app.Activity;
import android.os.Bundle;

public class TruledgerActivity extends Activity {
	String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
			"Proc-Type: 4,ENCRYPTED\n" +
			"DEK-Info: AES-256-CBC,00BE5CCFDDFEB7B6DBCCF5735E831BB6\n" +
			"\n" +
			"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\n" +
			"-----END RSA PRIVATE KEY-----\n";
	String password = "admin";
	String privstr, pubstr, genstr, sha1, sha256, sig;

	public static void println(String str) {
		System.out.println(str);
	}
	
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        Crypto crypto = new Crypto();
        KeyPair privkey;
        String privstr, pubstr;
        //String genstr;
        try {
        	privkey = crypto.decodeRSAPrivateKey(key, password);
        	privstr = crypto.encodeRSAPrivateKey(privkey, password);
        	pubstr = crypto.encodeRSAPublicKey(privkey);
        	PublicKey pubkey = crypto.decodeRSAPublicKey(pubstr);
        	pubstr = crypto.encodeRSAPublicKey(pubkey);
        	//KeyPair genkey = crypto.RSAGenerateKey(4096);
        	//genstr = crypto.encodeRSAPrivateKey(genkey, password);
        	this.privstr = privstr;
        	this.pubstr = pubstr;
        	//this.genstr = genstr;
        	String sha1 = crypto.sha1(privstr);
        	String sha256 = crypto.sha256(privstr);
        	String sig = crypto.sign("foo", privkey);
        	this.sig = sig;
        	this.sha1 = sha1;
        	this.sha256 = sha256;
        	println("privstr: " + privstr);
        	println("pubstr: " + pubstr);
        	println("sha1: " + sha1);
        	println("sha256: " + sha256);
        	println("sig: " + sig);
        } catch (IOException e) {}
    }
}