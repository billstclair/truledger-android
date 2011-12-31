package com.truledger.client;

import java.io.IOException;

import java.security.PublicKey;

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
	private Hashtable<String, PublicKey> mKeydict;
	private ServerGetter mServerGetter;
	private boolean mAlwaysVerifySigs = false;
	private boolean mVerifySigs = true;
	
	public interface ServerGetter {
		public String getServer();
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
	
	@SuppressWarnings("serial")
	public class ParseException extends Exception {
		public ParseException(String msg) {
			super(msg);
		}
		public ParseException (String msg, int at) {
			super (msg + " at " + at);
		}
	}

	/**
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
	
	private class Token {
		public int pos;
		public char tok;
		public String str;
		
		public Token(int pos, char tok, String str) {
			this.pos = pos;
			this.tok = tok;
			this.str = str;
		}
	}
	
	private class State {
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
	
	@SuppressWarnings("serial")
	public class Dict extends Hashtable<Object, Object> {
		public Object get(int key) {
			return this.get(new Integer(key));
		}
		public void put(int key, Object value) {
			this.put(new Integer(key), value);
		}
		public String stringGet(Object key) {
			return (String)this.get(key);
		}
		public String stringGet(int key) {
			return (String)this.get(key);
		}
	}
	
	@SuppressWarnings("serial")
	public class DictList extends Vector<Dict> {
	}
	
	/**
	 * Return a hash table, or signal en error, if the parse could not be done,
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
					if (key == null) throw new ParseException("Missing key", pos);
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
								throw new ParseException("Sianature without ID", pos);
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
				String dict1 = dict.stringGet("register");
				if (dict1 == null) dict1 = (String)dict.get("serverid");
				if (dict1 != null) {
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
/*		  
	(defun unsigned-message (msg)
	  "Return just the message part of a signed message, not including the signature.
	   Assumes that the message will parse."
	  (let ((pos (search "):" msg :from-end t)))
	    (if pos
	        (subseq msg 0 (1+ pos))
	        msg)))

	(defun first-message (msg)
	  "Return the first message in a list of them.
	   Assumes that message parses correctly."
	  (let ((pos 0))
	    (loop
	       (setq pos (position #\. msg :start (1+ pos)))
	       (unless pos (return msg))
	       (unless (eql (aref msg (1- pos)) #\\)
	         (return (subseq msg 0 pos))))))

	(defun match-args (parse pattern)
	  "parse is a hash table with numeric and string keys.
	   pattern is a list of (key . value) pairs.
	   a numeric key in pattern must match a numeric key in parse.
	   a non-numeric key in pattern must correspond to a numeric key in parse
	   at the element number in pattern or the same non-numeric key in parse.
	   the result maps the non-numeric keys and values in $pattern and
	   their positions, to the matching values in $parse."
	  (loop
	     with res = (make-hash-table :test 'equal)
	     with name
	     with optional
	     for elt in pattern
	     for i from 0
	     for key = (if (listp elt) (car elt) i)
	     for value = (if (listp elt) (cdr elt) elt)
	     do
	       (cond ((integerp key)
	              (setq name value
	                    optional nil))
	             (t
	              (setq name key
	                    optional t)))
	       (cond ((eq name :rest)
	              (loop
	                 for j from i
	                 for val = (gethash j parse)
	                 while val
	                 collect val into rest
	                 do
	                   (setf (gethash j res) val)
	                 finally
	                   (setf (gethash :rest res) rest))
	              (decf i))
	             (t (let ((val (gethash i parse)))
	                  (unless val (setq val (gethash name parse)))
	                  (when (and (not optional) (not val)) (return nil))
	                  (when val
	                    (setf (gethash name res) val
	                          (gethash i res) val)))))
	     finally
	       (maphash (lambda (key value)
	                  (declare (ignore value))
	                  (unless (or (eq key $PARSER-MSGKEY)
	                              (gethash key res))
	                    (return nil)))
	                parse)
	       (setf (gethash $PARSER-MSGKEY res)
	             (gethash $PARSER-MSGKEY parse))
	     (return res)))

	(defun getarg (key args)
	  (gethash key args))

	(defun (setf getarg) (value key args)
	  (setf (gethash key args) value))

	(defun format-pattern (pattern)
	  (let ((res "(")
	        (comma nil))
	    (loop for (key . value) across pattern
	       do
	         (when comma (setq res (strcat res ",")))
	         (setq comma t)
	       (if (numberp key)
	           (setq res (format nil "~a<~a>" res value))
	           (setq res (format nil "~a~a=<~a>" res key value))))
	    (setq res (strcat res ")"))
	    res))

	(defun remove-signatures (msg)
	  "Remove the signatures from a message"
	  (loop
	     with res = ""
	     do
	       (let ((tail (strstr msg #.(format nil "):~%")))
	             (extralen 1)
	             (matchlen 3)
	             (tail2 (strstr msg #.(format nil "\\)\\:~%"))))
	         (when (and tail2 (< (length tail2) (length tail)))
	           (setq tail tail2
	                 extralen 2
	                 matchlen 5))
	         (let* ((msglen (length msg))
	                (i (- msglen (length tail)))
	                dotpos leftpos commapos)
	           (when (> msglen 0)
	             (setq res (strcat res (subseq msg 0 (min msglen (+ i extralen))))))
	           (setq msg (and tail (subseq tail matchlen))
	                 dotpos (position #\. msg)
	                 leftpos (position #\( msg)
	                 commapos (position #\, msg))
	           (cond ((null dotpos)
	                  (setq dotpos leftpos))
	                 (leftpos
	                  (setq dotpos (min dotpos leftpos))))
	           (cond ((null dotpos)
	                  (setq dotpos commapos))
	                 (commapos
	                  (setq dotpos (min dotpos commapos))))
	           (let ((parenpos (position #\) msg)))
	             (cond ((and parenpos
	                         (or (not dotpos) (< parenpos dotpos)))
	                    (setq msg (subseq msg parenpos)))
	                   (dotpos
	                    (setq res (strcat res #.(format nil "~%")))
	                    (setq msg (subseq msg dotpos)))
	                   (t (loop-finish))))))
	     finally
	       (return (str-replace ",(" #.(format nil ",~%(") res))))

	(defmethod match-pattern ((parser parser) req &optional serverid)
	  (let* ((patterns (patterns))
	         (request (gethash 1 req))
	         (pattern (gethash request patterns)))
	    (unless pattern
	      (error "Unknown request: ~s" request))
	    (setq pattern (nconc `(,$CUSTOMER ,$REQUEST) pattern))
	    (let ((args (match-args req pattern)))
	      (unless args
	        (error "Request doesn't match pattern for ~s: ~s, ~s"
	               request
	               pattern
	               (get-parsemsg req)))
	      (let ((args-serverid (gethash $SERVERID args)))
	        (when args-serverid
	          (unless serverid
	            (let ((server-getter (parser-server-getter parser)))
	              (when server-getter
	                (setq serverid (funcall server-getter)))))
	          (unless (or (blankp serverid) (equal serverid args-serverid))
	            (error "serverid mismatch, sb: ~s, was: ~s"
	                   serverid args-serverid))))
	      (when (> (length (gethash $NOTE args)) 4096)
	        (error "Note too long. Max: 4096 chars"))
	      args)))

	(defmethod match-message ((parser parser) (msg string))
	  "Parse and match a message.
	   Returns a hash table parameter names to values."
	  (let ((reqs (parse parser msg)))
	    (match-pattern parser (car reqs))))
 */
	 
}
