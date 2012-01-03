package com.truledger.client.test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

import android.test.ActivityInstrumentationTestCase2;

import com.truledger.client.Client;
import com.truledger.client.ClientDB;
import com.truledger.client.Crypto;
import com.truledger.client.FSDB;
import com.truledger.client.Parser;
import com.truledger.client.T;
import com.truledger.client.TruledgerActivity;

public class TruledgerTest extends ActivityInstrumentationTestCase2<TruledgerActivity> {
	
	private static boolean runPubkeyGen = false;
	private static boolean runFSDBTest = false;

	private static final String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
			"Proc-Type: 4,ENCRYPTED\n" +
			"DEK-Info: AES-256-CBC,00BE5CCFDDFEB7B6DBCCF5735E831BB6\n" +
			"\n" +
			"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\n" +
			"-----END RSA PRIVATE KEY-----\n";
	private static final String password = "admin";
	
	private TruledgerActivity mCtx;

    public TruledgerTest() {
    	super("com.truledger.client", TruledgerActivity.class);
    }
    
    @Override
    protected void setUp() throws Exception {
    	super.setUp();
    	mCtx = this.getActivity();
    }
    
	public static void println(String str) {
		System.out.println(str);
	}
    
    public void testCrypto() {
		KeyPair privkey;
		String privstr, pubstr;
		//String genstr;
		try {
			privkey = Crypto.decodeRSAPrivateKey(key, password);
			privstr = Crypto.encodeRSAPrivateKey(privkey, password);
			pubstr = Crypto.encodeRSAPublicKey(privkey);
			PublicKey pubkey = Crypto.decodeRSAPublicKey(pubstr);
			pubstr = Crypto.encodeRSAPublicKey(pubkey);
			int privbits = Crypto.getKeyBits(privkey);
			int pubbits = Crypto.getKeyBits(pubkey);
			assertEquals(new Integer(privbits), new Integer(pubbits));
			assertTrue(privbits == 3072);
			
			String sha1 = Crypto.sha1(privstr);
			String sha256 = Crypto.sha256(privstr);
			
			String sig = Crypto.sign("foo", privkey);
			boolean sigok = Crypto.verify("foo", pubkey, sig);
			assertTrue(sigok);
			boolean sigbad = Crypto.verify("foo", pubkey, "badsig");
			assertFalse(sigbad);
			
			String text = "Hello";
			String cipherText = Crypto.RSAPubkeyEncrypt(text, pubkey);
			String plainText = Crypto.RSAPrivkeyDecrypt(cipherText, privkey);
			assertEquals(plainText, text);
			
			println("privstr: " + privstr);
			println("pubstr: " + pubstr);
			println("privbits: " + privbits);
			println("pubbits: " + pubbits);
			println("sha1: " + sha1);
			println("sha256: " + sha256);
			println("sig: " + sig);
			println("sigok: " + sigok);
			println("sigbad: " + sigbad);
			println("cipherText: " + cipherText);
			println("plainText: " + plainText);
		} catch (IOException e) {
			println("IOException: " + e);
			assertTrue(false);
		}
    }
    
    public void testPubkeyGen() {
    	if (runPubkeyGen) {
    		try {
    			KeyPair genkey = Crypto.RSAGenerateKey(4096);
    			String genstr = Crypto.encodeRSAPrivateKey(genkey, password);
    			println("genstr: " + genstr);
    		} catch (IOException e) {
    			println("IOException: " + e);  
    			assertTrue(false);
    		}
    	}
    }
    
    private static void writeFiles(FSDB db, String dirpath, int cnt) {
    	for (int i=0; i<cnt; i++) {
    		db.put(dirpath, ""+i, dirpath+"/"+i);
    	}
    }
    
    private static void readFiles(FSDB db, String dirpath, int cnt, String[] subdirs) {
    	String files[] = db.contents(dirpath);
    	int len = (files == null) ? 0 : files.length;
    	int subdirslen = (subdirs == null) ? 0 : subdirs.length;
    	int count = cnt + subdirslen;
    	assertTrue(dirpath + ": " + count + "==" + len, count == len);
    	for (int i=0; i<cnt; i++) {
    		String file = ""+i;
    		assertEquals(db.get(dirpath, file), dirpath+"/"+i);
    		assertTrue("Find " + file, Arrays.binarySearch(files, file) >= 0);
    	}
    	for (int i=0; i<subdirslen; i++) {
    		String file = subdirs[i];
    		assertTrue("Find " + file, Arrays.binarySearch(files, file) >= 0);
    	}
    }
    
    private static void readOrWriteFiles(FSDB db, String dirpath, int cnt, boolean write, 
    		String[] subdirs) {
    	if (write) writeFiles(db, dirpath, cnt);
    	else readFiles(db, dirpath, cnt, subdirs);
    }
    
    public void testFSDB() {
    	if (!runFSDBTest) return;
    	String dbname = "test";
    	mCtx.deleteDatabase(dbname);
    	FSDB db = new FSDB(mCtx, dbname);
    	try {
    		testFSDBInternal(db);
    	} finally {
    		db.close();
    		mCtx.deleteDatabase(dbname);
    	}
    }
    
    private static void testFSDBInternal(FSDB db) {
        final String dirs0[] = {"one", "two", "three"};
        final String dirs1[] = {"eine", "zwei"};
        final String dirs2[] = {"un", "deux"};
            
		int cnt0 = 0;
		int cnt1 = 0;
		int cnt2 = 0;
		int cnt;
		int totalcnt = 0;
		String dirpath;
		for (int pass=0; pass<=1; pass++) {
			boolean write = (pass == 0);
			cnt = 2;
			totalcnt += cnt;
			readOrWriteFiles(db, "", cnt, write, dirs0);
	    	for (int i=0; i<(dirs0.length); i++) {
				cnt0 = i+1;
				String dirpath0 = dirs0[i];
				dirpath = dirpath0;
				if (i > 0) {
					for (int j=0; j<(dirs1.length); j++) {
						cnt1 = j+1;
						String dirpath1 = dirs1[j];
						String dirpath01 = dirpath0 + "/" + dirpath1;
						dirpath = dirpath01;
						if (j > 0) {
							for (int k=0; k<(dirs2.length); k++) {
								cnt2 = k+1;
								dirpath = dirpath01 + "/" + dirs2[k];
								cnt = cnt0+cnt1+cnt2;
								totalcnt += cnt;
								readOrWriteFiles(db, dirpath, cnt, write, null);
							}
						} else {
							cnt = cnt0+cnt1;
							totalcnt += cnt;
							readOrWriteFiles(db, dirpath, cnt, write, null);
						}
					}
				} else {
					totalcnt += cnt0;
					readOrWriteFiles(db, dirpath, cnt0, write, null);
				}
			}
		}
		// Verify intermediate directories
		readFiles(db, "two", 0, dirs1);
		readFiles(db, "three", 0, dirs1);
		readFiles(db, "two/zwei", 0, dirs2);
		readFiles(db, "three/zwei", 0, dirs2);
		println("Total reads + writes: " + totalcnt);
    }
    
    private static Parser.DictList parse(Parser parser, String msg) {
    	try {
    		return parser.parse(msg);
    	} catch (Parser.ParseException e) {
    		println("Parse exception on " + msg + " - " + e);
    		assertTrue("Parse exception: " + e.getMessage(), false);
    		return null;
    	}
    }
    
    private class MessageSpec {
    	public Object[] elements;
    	public String[] names;
    	public MessageSpec(Object[] elements, String[] names) {
    		this.elements = elements;
    		this.names = names;
    	}
    }
    
    private String makeMessage(Object[] elements, KeyPair privkey) {
    	StringBuffer buf = new StringBuffer();
    	buf.append('(');
    	boolean first = true;
    	for (Object o: elements) {
    		if (!first) buf.append(',');
    		else first = false;
    		if (o instanceof String) {
    			buf.append((String)o);
    		} else if (o instanceof MessageSpec) {
    			buf.append(this.makeMessage(((MessageSpec)o).elements, privkey));
    		} else {
    			assertTrue("Bad message element", false);
    		}
    	}
    	buf.append(')');
    	String msg = buf.toString();
    	String sig = Crypto.sign(msg,  privkey);
    	return msg + ":" + sig;
    }
    
    private Parser.DictList doParserTest(Parser parser, MessageSpec spec, KeyPair privkey) throws Exception {
    	return this.doParserTest(parser, new MessageSpec[] {spec}, privkey);
    }
    
    private Parser.DictList doParserTest(Parser parser, MessageSpec[] specs, KeyPair privkey) throws Exception {
    	StringBuffer buf = new StringBuffer();
    	boolean first = true;
    	for (MessageSpec spec: specs) {
    		if (!first) buf.append('.');
    		else first = false;
    		assertTrue("Spec element length same as names", spec.elements.length == spec.names.length);
    		buf.append(this.makeMessage(spec.elements, privkey));
    	}
    	String msg = buf.toString();
    	Parser.DictList parselist = parse(parser, msg);
    	int len = parselist.size();
    	assertTrue("Parselist len same as specs", len == specs.length);
    	for (int i=0; i<len; i++) {
    		this.affirmParse(parselist.get(i), specs[i]);
    	}
    	if (len == 1) {
    		assertEquals("message matches", msg, Parser.getParseMsg(parselist.get(0)));
    	}
    	return parselist;
    }

	private void affirmParse(Parser.Dict parse, MessageSpec spec) {
		Object[] elements = spec.elements;
		String[] names = spec.names;
		for (int i=0; i<elements.length; i++) {
			Object element = elements[i];
			String name = names[i];
			Object elt = parse.get(i);
			if (element instanceof String) {
				String desc = "parse[" + i + "]==" + ((name==null)?element:"<"+name+">"); 
				assertEquals(desc, element, elt);
			} else {
				assertTrue("Subparse is a Parser.Dict", elt instanceof Parser.Dict);
				affirmParse((Parser.Dict)elt, (MessageSpec)element);
			}
		}
		assertNull("parse not too long", parse.get(elements.length));
	}
    
    public void testParser() {
    	ClientDB db = null;
    	try {
    		db = new ClientDB(mCtx);
    		ClientDB.PubkeyDB pubkeyDB = db.getPubkeyDB();
    		KeyPair privkey = Crypto.decodeRSAPrivateKey(key, password);
    		String pubstr = Crypto.encodeRSAPublicKey(privkey);
    		String id = Crypto.getKeyID(pubstr);
    		pubkeyDB.put(id, pubstr);
    		final String serverid = "940fcf32f4f7753529080da0ca026d5c2cc7abe1";
    		String req = "2182";
    		
    		Object[] elements = new Object[] {id, T.GETINBOX, serverid, req};
    		String[] names = new String[] {"id", null, T.SERVERID, null};
    		Parser parser = new Parser(pubkeyDB);
    		MessageSpec spec1 = new MessageSpec(elements, names);
    		Parser.DictList reqs1 = doParserTest(parser, spec1, privkey);
    		
    		elements = new Object[] {id, T.ATGETINBOX, spec1};
    		names = new String[] {T.CUSTOMER, null, T.MSG};
    		MessageSpec spec2 = new MessageSpec(elements, names);
    		Parser.DictList reqs2 = doParserTest(parser, spec2, privkey);

    		doParserTest(parser, new MessageSpec[] {spec1, spec2}, privkey);

    		// Test matcher
    		Parser.ServerGetter getter = new Parser.ServerGetter() {
    			public String getServer() {
    				return serverid;
    			}
    		};
    		parser.setServerGetter(getter);
    		
    		Parser.Dict match = parser.matchPattern(reqs1.get(0));
    		assertEquals("reqs1 customer", id, match.get(T.CUSTOMER));
    		assertEquals("reqs1 request", T.GETINBOX, match.get(T.REQUEST));
    		assertEquals("reqs1 serverid", serverid, match.get(T.SERVERID));
    		assertEquals("reqs1 req", req, match.get(T.REQ));
    		assertEquals("reqs1 msg", Parser.getParseMsg(reqs1.get(0)), Parser.getParseMsg(match));
    		
    		match = parser.matchPattern(reqs2.get(0));
    		assertEquals("reqs2 customer", id, match.get(T.CUSTOMER));
    		assertEquals("reqs2 request", T.ATGETINBOX, match.get(T.REQUEST));
    		assertEquals("reqs2 msg", Parser.getParseMsg(reqs2.get(0)), Parser.getParseMsg(match));
    		
    		Object msg = match.get(T.MSG);
    		assertTrue("msg is a dict", msg instanceof Parser.Dict);
    		Parser.Dict req21 = (Parser.Dict)msg;
    		match = parser.matchPattern(req21);
    		assertEquals("req21 customer", id, match.get(T.CUSTOMER));
    		assertEquals("req21 request", T.GETINBOX, match.get(T.REQUEST));
    		assertEquals("req21 serverid", serverid, match.get(T.SERVERID));
    		assertEquals("req21 req", req, match.get(T.REQ));
    		assertEquals("req21 msg", Parser.getParseMsg(req21), Parser.getParseMsg(match));
    	} catch (Exception e) {
			println("Exception: " + e.getMessage());
			assertTrue("Exception: " + e.getMessage(), false);
    	} finally {
    		if (db != null) db.close();
    	}
    }
    
    public void testServerProxy() {
    	Client client = new Client(mCtx);
    	Client.ServerProxy server = client.makeServerProxy("http://truledger.com/");
    	Parser.Dict req = null;
    	try {
    		String msg = server.post("(0,serverid,0):0");
    		println(msg);
    		Parser parser = client.getParser();
    		req = parser.matchMessage(msg);
    	} catch (Exception e) {
    		assertTrue(e.getClass().getName() + ": " + e.getMessage(), false);
    	} finally {
    		server.close();
    		client.close();
    	}
    	if (req != null) {
    		assertTrue("customer not blank", req.get(T.CUSTOMER) != null);
    		assertEquals("register message", req.get(T.REQUEST), T.REGISTER);
    		assertEquals("customer = serverid", req.get(T.CUSTOMER), req.get(T.SERVERID));
    	}
    }
}

//////////////////////////////////////////////////////////////////////
///
/// Copyright 2011 Bill St. Clair
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
