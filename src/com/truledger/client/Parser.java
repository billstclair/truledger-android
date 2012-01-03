package com.truledger.client;

import java.io.IOException;

import java.security.PublicKey;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Stack;
import java.util.Vector;

/**
 * Parse "(id,[key:]value,...):signature" into a hash table,
 * verifying signatures.
 * Can separate multiple top-level forms with periods.
 * Values can be (id,...):signature forms.
 */
public class Parser {
	
	private static final String $PARSER_MSGKEY = "%msg%";

	private FSDB mKeydb;
	private Hashtable<String, PublicKey> mKeydict = new Hashtable<String, PublicKey>();
	private ServerGetter mServerGetter;
	private boolean mAlwaysVerifySigs = false;
	private boolean mVerifySigs = true;
	
	public Parser(FSDB keydb) {
		this.mKeydb = keydb;
	}
	
	public static interface ServerGetter {
		public String getServer();
	}
	
	public ServerGetter getServerGetter () {
		return mServerGetter;
	}
	
	public void setServerGetter (ServerGetter getter) {
		mServerGetter = getter;
	}
	
	public boolean getAlwaysVerifySigs () {
		return mAlwaysVerifySigs;
	}
	
	public void setAlwaysVerifySigs (boolean value) {
		mAlwaysVerifySigs = value;
	}
	
	public boolean getVerifySigs () {
		return mVerifySigs;
	}

	public void setVerifySigs (boolean value) {
		mVerifySigs = value;
	}
	
	public void withVerifySigs (boolean value, Runnable thunk) {
		boolean oldValue = mVerifySigs;
		mVerifySigs = value;
		try {
			thunk.run();
		} finally {
	      mVerifySigs = oldValue;
		}
	}
	
	public static class ParseException extends Exception {
		private static final long serialVersionUID = 7806218768576438785L;
		public ParseException(String msg) {
			super(msg);
		}
		public ParseException (String msg, int at) {
			super (msg + " at " + at);
		}
	}

	/**
	 * Return a hash table, or signal en error, if the parse could not be done,
	 * or an ID couldn't be found, or a signature was bad.
	 * left-paren, right-paren, comma, colon, and period are special chars.
	 * They, and back-slash, are escaped by backslashes.
	 * Verifies sigs if setVerifySigs() was last called with a true value.
	 * @param string The string to parse
	 * @return A table mapping keys to values
	 */
	public DictList parse (String string) throws ParseException {
		return this.parse(string, mVerifySigs);
	}
	
	private static class Token {
		public int pos;
		public char tok;
		public String str;
		
		public Token(int pos, char tok, String str) {
			this.pos = pos;
			this.tok = tok;
			this.str = str;
		}
	}
	
	private static class State {
		public char state;
		public Dict dict;
		public int dictidx;
		public int start;
		public String key;

		public State(char state, Dict dict, int dictidx, int start, String key) {
			this.state = state;
			this.dict = dict;
			this.dictidx = dictidx;
			this.start = start;
			this.key = key;
		}
	}
	
	private static final int MAX_INTERNED_INTEGERS = 20;
	private static Integer[] internedIntegers = new Integer[MAX_INTERNED_INTEGERS];
	
	/**
	 * Like new Integer(num), but returns a shared Integer instance for small positive num
	 * @param num an integer
	 * @return new Integer(num), but with minimal consing
	 */
	public static Integer intern(int num) {
		Integer res;
		if (num>=0 && num<MAX_INTERNED_INTEGERS) {
			res = internedIntegers[num];
			if (res == null) {
				res = internedIntegers[num] = new Integer(num);
			}
		} else res = intern(num);
		return res;
	}
	
	public static class Dict extends Hashtable<Object, Object> {
		private static final long serialVersionUID = -8236347145013574201L;
		public Object get(int key) {
			return this.get(intern(key));
		}
		public void put(int key, Object value) {
			this.put(intern(key), value);
		}
		public String stringGet(Object key) {
			return (String)this.get(key);
		}
		public String stringGet(int key) {
			return (String)this.get(key);
		}
	}
	
	public static class DictList extends Vector<Dict> {
		private static final long serialVersionUID = -2669357239706314493L;
	}
	
	/**
	 * Return a hash table, or signal an error, if the parse could not be done,
	 * or an ID couldn't be found, or a signature was bad.
	 * left-paren, right-paren, comma, colon, and period are special chars.
	 * They, and back-slash, are escaped by backslashes
	 * @param string The string to parse
	 * @param verifySigs true if signatures should be verified
	 * @return A table mapping keys to values
	 */
	public DictList parse (String string, boolean verifySigs) throws ParseException {
		final char NULL_STATE = '\000';
		final char SIG_STATE = '\001';

		Token[] tokens =  this.tokenize(string);
		char state = NULL_STATE;
		DictList res = new DictList();
		Dict dict = null;
		int dictidx = -1;
		int start = 0;
		String id = null;
		String msg = null;
		String key = null;
		Object value = null;
		boolean needsig = false;
		Stack<State> stack = new Stack<State>();

		for (int i=0; i<tokens.length; i++) {
			boolean first = (i == 0);
			Token token = tokens[i];
			int pos = token.pos;
			char tok = token.tok;

			if (first && tok != '(') {
				throw new ParseException("Message does not begin with left paren.");
			}

			if (tok == '(') {
				needsig = true;
				if (dict!=null && state!=NULL_STATE && state != ':' && state!=',') {
					throw new ParseException("Open paren not after colon or comma", pos);
				}
				if (key!=null && state!=':') {
					throw new ParseException("Missing key", pos);
				}
				if (dict != null) {
					stack.push(new State(state, dict, dictidx, start, key));
					dict = null;
					dictidx = -1;
					key = null;
				}
				start = pos;
				state = '(';
			} else if (tok == ')') {
				if (state == ',') {
					if (key != null) throw new ParseException("Missing key", pos);
					if (dict == null) dict = new Dict();
					dict.put(++dictidx, (value==null) ? "" : value);
					value = null;
				} else if (state == ':') {
					if (dict == null) dict = new Dict();
					dict.put(key, (value==null) ? "" : value);
					value = null;
				} else if (state != NULL_STATE) {
					throw new ParseException("Close paren not after value", pos);
				}
				msg = string.substring(start, pos+1);
				state = ')';
			} else if (tok == ':') {
				if (state == ')') state = SIG_STATE;
				else if (value == null) {
					throw new ParseException("Missing key before colon", pos);
				} else {
					key = (String)value;
					value = null;
					state = ':';
				}
			} else if (tok == ',') {
				if (state == ':') {
					if (key == null) {
						throw new ParseException("Missing key");
					}
					if (dict == null) dict = new Dict();
					dict.put(key, (value==null) ? "" : value);
					key = null;
				} else {
					if (state!=NULL_STATE && state!=',' && state !='(') {
						throw new ParseException("Misplaced comma at " + pos + ", state: " + state);
					}
					if (dict == null) dict = new Dict();
					dict.put(++dictidx, (value==null) ? "" : value);
				}
				value = null;
				state = ',';
			} else if (tok == '.') {
				if (state!=NULL_STATE|| stack.size()>0) {
					throw new ParseException("Misplaced period", pos);
				}
				if (dict != null) res.add(dict);
				dict = null;
				dictidx = -1;
				key = null;
			} else {
				if (state=='(' || state==',' || state==':') value = token.str;
				else if (state == SIG_STATE) {
					id = (dict==null) ? null : dict.stringGet(0);
					if (id == null) {
						throw new ParseException("Signature without ID", pos);
					}
					String cmd;
					if (!(id.equals("0") &&
							((cmd=dict.stringGet(1)).equals("serverid") ||
							 cmd.equals("readdata"))))
						if (mVerifySigs || mAlwaysVerifySigs) {
							PublicKey pubkey = this.getPubkey(id, dict);
							if (pubkey == null) {
								throw new ParseException("Pubkey unknown for id: " + id, pos);
							}
							if (!Crypto.verify(msg, pubkey, token.str)) {
								throw new ParseException("Signature verification failed", pos);
							}
						}
					dict.put($PARSER_MSGKEY, string.substring(start, pos + token.str.length()));
					if (stack.size() > 0) {
						State pop = stack.pop();
						value = dict;
						state = pop.state;
						dict = pop.dict;
						dictidx = pop.dictidx;
						start = pop.start;
						key = pop.key;
						needsig = true;
					} else {
						res.add(dict);
						dict = null;
						dictidx = -1;
						needsig = false;
						state = NULL_STATE;
					}
				} else {
					throw new ParseException("Misplaced value", pos);
				}
			}
		}
		if (needsig) {
			throw new ParseException("Premature end of message");
		}
		return res;
	}
	
	private PublicKey getPubkey(String id, Dict dict) throws ParseException {
		PublicKey pubkey = (mKeydb!=null) ? mKeydict.get(id) : null;
		try {
			if (pubkey == null) {
				String dict1 = dict.stringGet(1);
				if (dict1.equals("register") || dict1.equals("serverid")) {
					String keystr = dict.stringGet(dict1.equals("register") ? 3 : 2);
					pubkey = Crypto.decodeRSAPublicKey(keystr);
					String pubkeyid = Crypto.getKeyID(keystr);
					mKeydict.put(id,  pubkey);
					if (!id.equals(pubkeyid)) pubkey = null;				
				}
			}
			if (pubkey == null) {
				String keystr = null;
				if (mKeydb != null) keystr = mKeydb.get(null, id);
				if (keystr != null) {
					if (!id.equals(Crypto.getKeyID(keystr))) {
						throw new ParseException("Pubkey doesn't match id: " + id);
					}
					pubkey = Crypto.decodeRSAPublicKey(keystr);
					mKeydict.put(id, pubkey);
				}
			}
		} catch (IOException e) {
			throw new ParseException("Error parsing public key: " + e.getMessage());
		}
		return pubkey;
	}
	
	private Token[] tokenize(String string) {
		Vector<Token> res = new Vector<Token>();
		int realstart = -1;
		int start = -1;
		String delims = "(:,).";
		boolean escaped = false;
		String substr = "";
		int len = string.length();
		for (int i=0; i<len; i++) {
			char chr = string.charAt(i);
			if (!escaped && delims.indexOf((int)chr) >= 0) {
				if (start >= 0) {
					res.add(new Token(realstart, '\000', substr + string.substring(start, i)));
					start = -1;
					realstart = -1;
					substr = "";
				}
				res.add(new Token(i, chr, null));
			} else if (!escaped && chr=='\\') {
				escaped = true;
				if (start >= 0) {
					substr = substr + string.substring(start, i);
					start = i + 1;
				}
			} else {
				if (start < 0) {
					start = i;
					realstart = i;
				}
				escaped = false;
			}
		}
		if (start >= 0) {
			res.add(new Token(realstart, '\000', substr + string.substring(start, len)));
		}
		return res.toArray(new Token[res.size()]);
	}
	
	/**
	 * Get the string that parsed into a parse() output
	 * @param parse One of the elements of the DictList returned from parse();
	 * @return The message string that parsed into parse.
	 */
	public static String getParseMsg(Dict parse) {
		return parse.stringGet($PARSER_MSGKEY);
	}
	
	/**
	 * Return just the message part of a signed message
	 * @param msg signed message
	 * @return unsigned message
	 */
	public static String unsignedMessage(String msg) {
		int pos = msg.indexOf("):");
		return (pos >= 0) ? msg.substring(0, pos) : msg;
	}
	
	/**
	 * Return the first message of a compound message
	 * @param msg compound message
	 * @return first message (before first-non-escaped period)
	 */
	public static String firstMessage(String msg) {
		int len = msg.length();
		boolean escaped = false;
		for (int i=0; i<len; i++) {
			if (escaped) escaped = false;
			else {
				char chr = msg.charAt(i);
				if (chr == '\\') escaped = true;
				else if (chr == '.') return msg.substring(0, i);
			}
		}
		return msg;
	}
	
	public static class OptionalString {
		public String string;
		
		public OptionalString(String string) {
			this.string = string;
		}
	}
	
	public static class StringList extends Vector<String> {
		private static final long serialVersionUID = 5736725495564468383L;
	}
	
	public static final String $REST_KEY = "rest";
	
	/**
	 * Assign names from pattern to elements in parse
	 * @param parse An element of the DictList returned from parse()
	 * @param pattern An array of String and OptionalString instances
	 * @return A copy of parse, with names added from pattern,
	 *         or null if pattern doesn't match parse
	 */
	public Dict matchArgs(Dict parse, Object[] pattern) throws ParseException {
		Dict res = new Dict();
		String name;
		boolean isOptional;
		for (int i=0; i<pattern.length; i++) {
			Object elt = pattern[i];
			if (elt instanceof OptionalString) {
				name = ((OptionalString)elt).string;
				isOptional = true;
			} else if (elt instanceof String) {
				name = (String)elt;
				isOptional = false;
			} else {
				throw new ParseException("Bad element type in pattern");
			}

			if (name.equals($REST_KEY)) {
				StringList list = new StringList();
				for (int j=i;;j++) {
					String val = parse.stringGet(j);
					if (val == null) break;
					list.add(val);
					res.put(j,  val);
				}
				res.put($REST_KEY, list);
			} else {
				Object val = parse.get(i);
				if (val == null) val = parse.get(name);
				if (val == null) {
					if (!isOptional) return null;
				} else {
					res.put(name, val);
					res.put(i,  val);
				}
			}
		}
		String msg = null;
		Enumeration<Object> keys = parse.keys();
		while (keys.hasMoreElements()) {
			Object key = keys.nextElement();
			if (key.equals($PARSER_MSGKEY)) {
				msg = parse.stringGet(key);
			} else if (res.get(key) == null) {
				return null;
			}
		}
		if (msg != null) res.put($PARSER_MSGKEY, msg);
		return res;
	}
	
	/**
	 * Remove the signatures from a message string
	 * @param msg the message string
	 * @return msg sans signatures
	 */
	public static String removeSignatures(String msg) {
		StringBuffer buf = new StringBuffer(msg.length());
		while (true) {
			String tail = Utility.strstr(msg, "):\n");
			int extralen = 1;
			int matchlen = 3;
			String tail2 = Utility.strstr(msg,  "\\)\\:\n");
			if ((tail2 != null) && (tail==null || tail2.length() < tail.length())) {
				tail = tail2;
				extralen = 2;
				matchlen = 5;
			}
			int msglen = msg.length();
			int i = msglen - tail.length();
			if (msglen > 0) buf.append(msg.substring(0, Math.min(msglen, i + extralen)));
			msg = (tail != null) ? tail.substring(matchlen) : "";
			int dotpos = msg.indexOf('.');
			int leftpos = msg.indexOf('(');
			int commapos = msg.indexOf(',');
			if (dotpos < 0) dotpos = leftpos;
			else if (leftpos >= 0) dotpos = Math.min(dotpos, leftpos);
			if (dotpos < 0) dotpos = commapos;
			else if (commapos >= 0) dotpos = Math.min(dotpos,  commapos);
			int parenpos = msg.indexOf(')');
			if (parenpos>=0 && (dotpos<0 || parenpos<dotpos)) msg = msg.substring(parenpos);
			else if (dotpos >= 0) {
				buf.append("\n");
				msg = msg.substring(dotpos);
			} else break;
		}
		return buf.toString().replace(",(", ",\n(");
	}

	/**
	 * Find and match a pattern for a message
	 * @param req The parsed message to match
	 * @param serverid The ID of the server, if known. Will use getServerGetter().getServer() otherwise
	 * @return A matched message, as returned from matchArgs()
	 * @throws ParseException If req's request is unknown, req doesn't match any of the patterns, or
	 *         req's server doesn't match the serverid.
	 */
	public Dict matchPattern(Dict req, String serverid) throws ParseException {
		PatternHash patterns = getPatterns();
		String request = req.stringGet(1);
		Object[] pattern = patterns.get(request);
		if (pattern == null) throw new ParseException("Unknown request: " + request);
		Dict args = this.matchArgs(req,  pattern);
		if (args == null) throw new ParseException("Request doesn't match pattern for "
		  + request + ": " + pattern + ", " + getParseMsg(req));
		String argsServerid = args.stringGet(T.SERVERID);
		if (argsServerid != null) {
			if (serverid == null) {
				if (mServerGetter != null) {
					serverid = mServerGetter.getServer();
				}
			}
			if (!Utility.isBlank(serverid) && !serverid.equals(argsServerid)) {
				throw new ParseException("serverid mismatch, sb: " + serverid + ", was: " + argsServerid);
			}
		}
		return args;
	}
	
	public Dict matchPattern(Dict req) throws ParseException {
		return this.matchPattern(req, null);
	}

	/**
	 * Parse and match a message.
	 * @param msg The message to parse and match
	 * @return matchPattern(parse(msg)[0])
	 * @throws ParseException if parsing or matching fails
	 */
	public Dict matchMessage(String msg) throws ParseException {
		DictList reqs = this.parse(msg);
		return this.matchPattern(reqs.elementAt(0));
	}
	
	public static class PatternHash extends Hashtable<String, Object[]> {
		private static final long serialVersionUID = -3417530618975114989L;
		public PatternHash() {
			super();
		}
		public PatternHash(int size) {
			super(size);
		}
	}

	private static PatternHash patterns = null;
	
	public static PatternHash getPatterns() {
		PatternHash pats = patterns;
		if (pats == null) {
			int len = patternsource.length;
			pats = new PatternHash(len);
			for (int i=0; i<len; i++) {
				Object[] pat = patternsource[i];
				String request = (String)pat[0];
				int patlen = pat.length;
				Object[] pattern = new Object[patlen+1];
				pattern[0] = T.CUSTOMER;
				pattern[1] = T.REQUEST;
				for (int j=1; j<patlen; j++) {
					pattern[j+1] = pat[j];
				}
				pats.put(request,  pattern);
			}
			patterns = pats;
		}
		return pats;
	}
	
	private static OptionalString os(String str) {
		return new OptionalString(str);
	}
		
	private static Object[][] patternsource =
		{
		{T.SERVERID, T.PUBKEY, os(T.COUPON)},
		{T.ID, T.SERVERID, T.ID},
		{T.BALANCE, T.SERVERID, T.TIME, T.ASSET, T.AMOUNT, os(T.ACCT)},
		{T.OUTBOXHASH, T.SERVERID, T.TIME, T.COUNT, T.HASH, os(T.TWOPHASECOMMIT)},
		{T.BALANCEHASH, T.SERVERID, T.TIME, T.COUNT, T.HASH, os(T.TWOPHASECOMMIT)},
		{T.GETFEES, T.SERVERID, T.REQ, os(T.OPERATION)},
		{T.SETFEES, T.TIME, T.COUNT},
		{T.SPEND, T.SERVERID, T.TIME, T.ID, T.ASSET, T.AMOUNT, os(T.NOTE)},
		{T.GETASSET, T.SERVERID, T.REQ, T.ASSET},
		{T.ASSET, T.SERVERID, T.ASSET, T.SCALE, T.PRECISION, T.ASSETNAME},
		{T.STORAGE, T.SERVERID, T.TIME, T.ASSET, T.PERCENT},
		{T.STORAGEFEE, T.SERVERID, T.TIME, T.ASSET, T.AMOUNT},
		{T.FRACTION, T.SERVERID, T.TIME, T.ASSET, T.AMOUNT},
		{T.REGISTER, T.SERVERID, T.PUBKEY, os(T.NAME)},
		{T.GETREQ, T.SERVERID},
		{T.SPENDACCEPT, T.SERVERID, T.TIME, T.ID, os(T.NOTE)},
		{T.SPENDREJECT, T.SERVERID, T.TIME, T.ID, os(T.NOTE)},
		{T.GETOUTBOX, T.SERVERID, T.REQ},
		{T.GETBALANCE, T.SERVERID, T.REQ, os(T.ACCT), os(T.ASSET)},
		{T.GETINBOX, T.SERVERID, T.REQ},
		{T.PROCESSINBOX, T.SERVERID, T.TIME, T.TIMELIST},
		{T.STORAGEFEES, T.SERVERID, T.REQ},
		{T.GETTIME, T.SERVERID, T.REQ},
		{T.COUPONENVELOPE, T.ID, T.ENCRYPTEDCOUPON},
		{T.GETVERSION, T.SERVERID, T.REQ},
		{T.VERSION, T.VERSION, T.TIME},
		{T.WRITEDATA, T.SERVERID, T.TIME, T.ANONYMOUS, T.KEY, T.DATA},
		{T.READDATA, T.SERVERID, T.REQ, T.KEY, os(T.SIZE)},
		{T.GRANT, T.SERVERID, T.TIME, T.ID, T.PERMISSION, os(T.GRANT)},
		{T.DENY, T.SERVERID, T.REQ, T.ID, T.PERMISSION},
		{T.PERMISSION, T.SERVERID, T.REQ, os(T.GRANT)},
		{T.AUDIT, T.SERVERID, T.REQ, T.ASSET},
		{T.OPENSESSION, T.SERVERID, T.REQ, os(T.TIMEOUT), os(T.INACTIVETIME)},
		{T.CLOSESESSION, T.SERVERID, T.REQ, T.SESSIONID},
		{T.BACKUP, T.REQ, $REST_KEY},
		{T.COMMIT, T.SERVERID, T.TIME},
		{T.GETFEATURES, T.SERVERID, T.REQ},
		{T.FEATURES, T.SERVERID, T.TIME, T.FEATURES},
		{T.LASTTRANSACTION, T.SERVERID, T.REQ},

		//, Server, signed, messages
		{T.FAILED, T.MSG, T.ERRMSG},
		{T.TOKENID, T.TOKENID},
		{T.REGFEE, T.SERVERID, T.TIME, T.ASSET, T.AMOUNT},
		{T.TRANFEE, T.SERVERID, T.TIME, T.ASSET, T.AMOUNT},
		{T.FEE, T.SERVERID, T.TIME, T.OPERATION, T.ASSET, T.AMOUNT},
		{T.TIME, T.ID, T.TIME},
		{T.INBOX, T.TIME, T.MSG},
		{T.REQ, T.ID, T.REQ},
		{T.COUPON, T.SERVERURL, T.COUPON, T.ASSET, T.AMOUNT, os(T.NOTE)},
		{T.COUPONNUMBERHASH, T.COUPON},
		{T.ATREGISTER, T.MSG},
		{T.ATOUTBOXHASH, T.MSG},
		{T.ATBALANCEHASH, T.MSG},
		{T.ATGETINBOX, T.MSG},
		{T.ATBALANCE, T.MSG},
		{T.ATSETFEES, T.MSG},
		{T.ATSPEND, T.MSG},
		{T.ATTRANFEE, T.MSG},
		{T.ATFEE, T.MSG},
		{T.ATASSET, T.MSG},
		{T.ATSTORAGE, T.MSG},
		{T.ATSTORAGEFEE, T.MSG},
		{T.ATFRACTION, T.MSG},
		{T.ATPROCESSINBOX, T.MSG},
		{T.ATSTORAGEFEES, T.MSG},
		{T.ATSPENDACCEPT, T.MSG},
		{T.ATSPENDREJECT, T.MSG},
		{T.ATGETOUTBOX, T.MSG},
		{T.ATCOUPON, T.COUPON, T.SPEND},
		{T.ATCOUPONENVELOPE, T.MSG},
		{T.ATWRITEDATA, T.ID, T.TIME, T.ANONYMOUS, T.KEY},
		{T.ATREADDATA, T.ID, T.TIME, T.DATA},
		{T.ATGRANT, T.MSG},
		{T.ATDENY, T.MSG},
		{T.ATPERMISSION, T.MSG},
		{T.ATAUDIT, T.MSG},
		{T.ATOPENSESSION, T.MSG, T.CIPHERTEXT},
		{T.CLOSESESSION, T.MSG},
		{T.ATBACKUP, T.REQ},
		{T.ATCOMMIT, T.MSG}
		};
	 
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
