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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMReader;
import org.spongycastle.openssl.PEMWriter;
import org.spongycastle.openssl.PasswordFinder;

public class Crypto {
	private static boolean isProviderInitialized = false;
	private static SecureRandom random;
	private static double ver;
	public static Exception lastErr;

	private static void initialize() {
		if (!isProviderInitialized) {
			Security.addProvider(new BouncyCastleProvider());
			random = new SecureRandom();
			double ver = Security.getProvider("SC").getVersion();
			Crypto.ver = ver;
			isProviderInitialized = true;
		}
	}
	
	public Crypto() {
		initialize();
	}

	public static SecureRandom getRandom() {
		initialize();
		return random;
	}
	
	public static KeyPair RSAGenerateKey(int keysize, BigInteger exponent) {
		initialize();
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
		AlgorithmParameterSpec spec = new RSAKeyGenParameterSpec(keysize, exponent);
		try {
			kpg.initialize(spec, getRandom());
		} catch (InvalidAlgorithmParameterException e) {
			return null;
		}
		return kpg.genKeyPair();
	}

	final public static BigInteger defaultExponent = BigInteger.valueOf(65537);

	public static KeyPair RSAGenerateKey(int keysize) {
		return RSAGenerateKey(keysize, defaultExponent);
	}

	public static KeyPair decodeRSAPrivateKey(String key, final String password) throws IOException {
		initialize();
		Reader keyReader = new StringReader(key.trim());
		PasswordFinder pwd = new PasswordFinder() {
			public char[] getPassword() {
				return password.toCharArray();
			}
		};
		PEMReader reader = new PEMReader(keyReader, pwd);
		return (KeyPair)reader.readObject();
	}

	public static String encodeRSAPrivateKey(KeyPair key, final String password) throws IOException {
		initialize();
		StringWriter keyWriter = new StringWriter();
		PEMWriter writer = new PEMWriter(keyWriter);
		writer.writeObject(key, "AES-256-CBC", password.toCharArray(), getRandom());
		writer.flush();
		return keyWriter.getBuffer().toString();
	}

	public static PublicKey decodeRSAPublicKey(String key) throws IOException {
		initialize();
		Reader keyReader = new StringReader(key.trim());
		PEMReader reader = new PEMReader(keyReader);
		return (PublicKey)reader.readObject();
	}

	public static PublicKey decodeRSAPublicKey(PublicKey key) {
		return key;
	}

	public static String encodeRSAPublicKey(PublicKey key) throws IOException {
		initialize();
		StringWriter keyWriter = new StringWriter();
		PEMWriter writer = new PEMWriter(keyWriter);
		writer.writeObject(key);
		writer.flush();
		return keyWriter.getBuffer().toString();
	}

	public static String encodeRSAPublicKey(KeyPair key) throws IOException {
		return encodeRSAPublicKey(key.getPublic());
	}

	public static String sha1(byte[] buf) {
		return digest(buf, "SHA1");
	}

	public static String sha1(String str) {
		return digest(str, "SHA1");
	}

	public static String sha256(byte[] buf) {
		return digest(buf, "SHA256");
	}

	public static String sha256(String str) {
		return digest(str, "SHA256");
	}

	public static String digest(byte[] buf, String algorithm) {
		initialize();
		MessageDigest dig;
		try {
			dig = MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
		dig.update(buf);
		return Utility.bin2hex(dig.digest());
	}

	public static String digest(String str, String algorithm) {
		return digest(str.getBytes(), algorithm);
	}

	public static String sign(String data, KeyPair key) {
		return sign(data, key.getPrivate());
	}

	final private static String SIGNING_ALGORITHM = "SHA1withRSA";

	public static String sign(String data, PrivateKey key) {
		initialize();
		try {
			Signature signer = Signature.getInstance(SIGNING_ALGORITHM);
			signer.initSign(key);
			signer.update(data.getBytes());
			byte[] signature = signer.sign();
			String res = Utility.base64Encode(signature);
			return res;
		} catch (Exception e) {
			System.out.println(e.toString());
			return null;
		}
	}

	public static boolean verify(String data, PublicKey key, String signature) {
		initialize();
		try {
			Signature signer = Signature.getInstance(SIGNING_ALGORITHM);
			signer.initVerify(key);
			signer.update(data.getBytes());
			byte[] sig = Utility.base64Decode(signature);
			return signer.verify(sig);
		} catch (Exception e) {
			return false;
		}
	}

	public static int getKeyBits(KeyPair key) {
		return getKeyBits(key.getPrivate());
	}

	public static int getKeyBits(PrivateKey key) {
		initialize();
		return ((RSAKey)key).getModulus().bitLength();
	}

	public static int getKeyBits(PublicKey key) {
		initialize();
		return ((RSAKey)key).getModulus().bitLength();
	}
	
	public static String getKeyID(String key) {
		initialize();
		return sha1(key.trim());
	}
	
	private static Cipher getRSACipher () throws NoSuchAlgorithmException, NoSuchPaddingException {
		initialize();
		return Cipher.getInstance("RSA/None/PKCS1Padding");
	}

	public static String RSAPubkeyEncrypt(String plainText, String keytext) throws IOException {
		return RSAPubkeyEncrypt(plainText, decodeRSAPublicKey(keytext));
	}
	
	public static String RSAPubkeyEncrypt(String plainText, PublicKey key) {
		initialize();
		try {
			Cipher cipher = getRSACipher();
			cipher.init(Cipher.ENCRYPT_MODE, key, getRandom());
			byte[] plainBytes = plainText.getBytes();
			int blockSize = cipher.getBlockSize();
			int outputSize = cipher.getOutputSize(blockSize);
			int inLen = plainBytes.length;
			int fullBlockCount = inLen / blockSize;
			int outLen = fullBlockCount * outputSize;
			boolean needExtraBlock = false;
			if (fullBlockCount * blockSize < inLen) outLen += outputSize;
			else {
				for (int i=inLen-1; i>= 0; --i) {
					int b = (int)plainBytes[i] & 0xff;
					if (b == 0x80) {
						if (i == inLen-1) break;
						needExtraBlock = true;
						outLen += outputSize;
						break;
					}
					if (b != 0) break;
				}
			}
			byte[] cipherBytes = new byte[outLen];
			int inOffset = 0;
			int outOffset = 0;
			for (int i=0; i<fullBlockCount; i++) {
				outOffset += cipher.update(plainBytes, inOffset, blockSize, cipherBytes, outOffset);
				inOffset += blockSize;
			}
			if (inOffset < inLen || needExtraBlock) {
				byte[] lastBlock = new byte[blockSize];
				int cnt = inLen - inOffset;
				for (int i=0; i<cnt; i++) {
					lastBlock[i] = plainBytes[inOffset++];
				}
				lastBlock[cnt] = (byte)0x80;
				for (int i=cnt+1; i<blockSize; i++) lastBlock[i] = 0;
				outOffset += cipher.update(lastBlock, 0, blockSize, cipherBytes, outOffset);
			}
			cipher.doFinal(plainBytes, 0, 0, cipherBytes, outOffset);
			return Utility.base64Encode(cipherBytes);
		} catch (Exception e) {
			return null;
		}
	}

	public static String RSAPrivkeyDecrypt(String cipherText, PrivateKey key) {
		initialize();
		try {
			Cipher cipher = getRSACipher();
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] cipherBytes = Utility.base64Decode(cipherText);
			int blockSize = cipher.getBlockSize();
			int outputSize = cipher.getOutputSize(blockSize);
			int inLen = cipherBytes.length;
			int blockCount = inLen / blockSize;
			int inOffset = 0;
			int outOffset = 0;
			byte[] plainBytes = new byte[blockCount * outputSize];
			for (int i=0; i<blockCount; i++) {
				outOffset += cipher.update(cipherBytes, inOffset, blockSize, plainBytes, outOffset);
				inOffset += blockSize;
			}
			int finalLen = cipher.doFinal(cipherBytes, inOffset, inLen - inOffset, plainBytes, outOffset);
			int outSize = outOffset + finalLen;
			for (int i=outSize-1; i>=outOffset; --i) {
				int b = (int)plainBytes[i] & 0xff;
				if (b == 0x80) {
					if (i == outSize-1) break;
					outSize = i;
					break;
				}
				if (b != 0) {
					outSize = i+1;
					break;
				}
			}
			return new String(plainBytes, 0, outSize);
		} catch (Exception e) {
			lastErr = e;
			return null;
		}
	}

	public static String RSAPrivkeyDecrypt(String cipherText, KeyPair key) {
		return RSAPrivkeyDecrypt(cipherText, key.getPrivate());
	}

	public static double getVer() {
		initialize();
		return ver;
	}
	
	/**
	 * Return a 16-byte random byte array
	 * @param base64Buf if non-null, base64Buf[0] will be set with the base64 encoding of the return value
	 * @return
	 */
	public static byte[] newCryptoSessionPassword(String[] base64Buf) {
		byte[] bytes = new byte[16];
		random.nextBytes(bytes);
		if (base64Buf != null) base64Buf[0] = Utility.base64Encode(bytes);
		return bytes;
	}
	
	public static Cipher AES_CIPHER = null;
	
	public static Cipher aesCipher () {
		if (AES_CIPHER != null) return AES_CIPHER;
		try {
			AES_CIPHER = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		} catch (Exception e) {
		}
		return AES_CIPHER;
	}
	
	// From http://www.javamex.com/tutorials/cryptography/block_modes_java.shtml
	public static String aesEncrypt(String plaintext, byte[] password, String[] ivBuf) {
		try {
			Cipher c = aesCipher();
			SecretKeySpec k = new SecretKeySpec(password, "AES");
			c.init(Cipher.ENCRYPT_MODE, k);
			// Could do this with a limited size buffer, but note sizes are already liimted to 4K, so it's probably OK
			byte[] bytes = plaintext.getBytes();
			byte[] cipherText = c.doFinal(bytes);
			ivBuf[0] = Utility.base64Encode(c.getIV());
			return Utility.base64Encode(cipherText);
		} catch (Exception e) {
			return "";
		}
	}
	
	public static String aesDecrypt(String cipherText, byte[] password, String iv) {
		try {
			Cipher c = aesCipher();
			SecretKeySpec k = new SecretKeySpec(password, "AES");
			byte[] ivbytes = Utility.base64Decode(iv);
			c.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(ivbytes));
			byte[] bytes = Utility.base64Decode(cipherText);
			byte[] plainText = c.doFinal(bytes);
			return new String(plainText);
		} catch (Exception e) {
			return "";
		}
	}
	
	public static String encryptNote(FSDB pubkeydb, String note, String... ids) {
		if (Utility.isBlank(note)) return note;
		String[] base64Buf = new String[1];
		byte[] password = newCryptoSessionPassword(base64Buf);
		String passwordString = base64Buf[0];
		String[] ivbuf = new String[1];
		String cipherText = aesEncrypt(note, password, ivbuf);
		if (Utility.isBlank(cipherText)) return "";
		String ivstr = ivbuf[0];
		String keys = "";
		try {
			for (int i=0; i<ids.length; i++) {
				String id = ids[i];
				String pubkey = pubkeydb.get(id);
				if (pubkey == null) return "";
				String key = RSAPubkeyEncrypt(passwordString, pubkey);
				if (i > 0) keys += '|';
				keys += id + ':' + key; 
			}
		} catch (Exception e) {
			return "";
		}
		return "[" + keys + ',' + ivstr + ',' + cipherText + ']';
	}
	
	public static String decryptNote(String id, KeyPair privkey, String encryptedNote) {
		if (encryptedNote.equals("")) return "";
		try {
			String[] kic = Utility.parseSquareBracketString(encryptedNote);
			if (kic.length != 3) return "";
			String keys = kic[0];
			String iv = kic[1];
			String cipherText = kic[2];
			String[] idKeyPairs = Utility.splitString('|', keys);
			for (String pair: idKeyPairs) {
				String[] idAndKey = Utility.splitString(':', pair);
				if (id.equals(idAndKey[0])) {
					String passwordString = RSAPrivkeyDecrypt(idAndKey[1], privkey);
					byte[] password = Utility.base64Decode(passwordString);
					return aesDecrypt(cipherText, password, iv);
				}
			}
		} catch (Exception e) {
			return "";
		}
		// No password for ID, return null
		return "";
	}
}

//////////////////////////////////////////////////////////////////////
///
/// Copyright 2011-2012 Bill St. Clair
///
/// Licensed under the Apache License, Version 2.0 (the "License")
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions
/// and limitations under the License.
///
//////////////////////////////////////////////////////////////////////
