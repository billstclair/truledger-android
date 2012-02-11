package com.truledger.client;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Stack;

/**
 * A lisp-like list, with parsing and printing 
 * @author billstclair
 *
 */
public class LispList extends ArrayList<Object> {
	/**
	 * A lisp-like interned keyword
	 */
	public static class Keyword {
		private String namestring;
		private Keyword(String namestring) {
			this.namestring = namestring;
		}
		public String getNamestring() {
			return namestring;
		}
		public String toString() {
			return ":" + namestring;
		}

		/**
		 * Map strings to Keyword instances for internKeyword
		 */
		private static final HashMap<String, Keyword> keywordHash = new HashMap<String, Keyword>();

		/**
		 * Intern a string into a keyword
		 * @param namestring
		 * @return
		 */
		public static Keyword intern(String namestring) {
			namestring = namestring.toUpperCase();
			Keyword res = keywordHash.get(namestring);
			if (res != null) return res;
			res = new Keyword(namestring);
			keywordHash.put(namestring,  res);
			return res;
		}
	}

	private static final long serialVersionUID = -7322719017873541150L;

	/**
	 * Default constructor
	 */
	public LispList() {
		super();
	}

	/**
	 * Create a LispList with initially enough space for size elements
	 * @param size
	 */
	public LispList(int size) {
		super(size);
	}

	/**
	 * Convert an array into a LispList
	 * @param array
	 * @return
	 */
	public static LispList valueOf(Object[] array) {
		LispList res = new LispList(array.length);
		for (Object elt: array) {
			res.add(elt);
		}
		return res;
	}

	/**
	 * Like Lisp's prin1-to-string function
	 */
	public String prin1ToString() throws Exception {
		StringBuilder res = new StringBuilder();
		this.prin1ToBuf(res);
		return res.toString();
	}

	/**
	 * Append the printed representation of this LispList to res
	 * @param res
	 */
	public void prin1ToBuf(StringBuilder res) throws Exception {
		res.append('(');
		boolean first = true;
		for (Object elt: this) {
			if (first) first = false;
			else res.append(' ');
			if (elt instanceof String) {
				res.append('"');
				Utility.escapeStringToBuf((String)elt, '\\', "\"", res);
				res.append('"');
			} else if (elt instanceof Keyword) {
				res.append(elt.toString());
			} else if (elt instanceof LispList) {
				((LispList)elt).prin1ToBuf(res);
			} else {
				throw new Exception("Only strings, keywords, and Lists supported");
			}
		}
		res.append(')');
	}

	public static Character LEFTPAREN = new Character('(');
	public static Character RIGHTPAREN = new Character(')');

	/**
	 * Parse string into a List, much like Lisp's READ
	 * @param string
	 * @return
	 */
	public static LispList parse(String string) throws Exception {
		LispList tokens = tokenize(string);
		LispList res = new LispList();
		Stack<LispList> stack = null;
		int size = tokens.size();
		if (size == 0) return res;
		if (tokens.get(0) != LEFTPAREN) throw new Exception("List doesn't begin with left paren");
		for (int i=1; i<size; i++) {
			Object tok = tokens.get(i);
			if (tok == LEFTPAREN) {
				if (stack == null) stack = new Stack<LispList>();
				stack.push(res);
				res = new LispList();
				continue;
			} else if (tok == RIGHTPAREN) {
				if (stack==null || stack.size()==0) {
					if (i+1 < size) throw new Exception("Garbage after final closing paren");
					break;
				} else {
					tok = res;
					res = stack.pop();
				}
			} 
			res.add(tok);
		}
		return res;
	}
	
	/**
	 * Convert string into a LispList of tokens
	 * Each token is either LEFTPAREN, RIGHTPARENT, a string, or a Keyword
	 * @param string
	 * @return
	 * @throws Exception
	 */
	public static LispList tokenize(String string) throws Exception {
		LispList res = new LispList();
		int start = 0;
		int len = string.length();
		boolean escaped = false;
		boolean instring = false;
		boolean inkeyword = false;
		StringBuilder buf = null;
		for (int i=0; i<len; i++) {
			char chr = string.charAt(i);
			if (instring) {
				if (escaped) escaped = false;
				else if (chr == '"') {
					instring = false;
					buf.append(string.substring(start, i));
					res.add(buf.toString());
					buf.setLength(0);
				} else if (chr == '\\') {
					escaped = true;
					buf.append(string.substring(start, i));
					start = i+1;
				}
			} else if (inkeyword) {
				if (" :\n\"".indexOf(chr) >= 0) {
					res.add(Keyword.intern(string.substring(start, i)));
					inkeyword = false;
					i--;
				}
			} else if (chr == '"') {
				instring = true;
				if (buf == null) buf = new StringBuilder();
				start = i+1;
			} else if (chr == ':') {
				inkeyword = true;
				start = i+1;
			}
			else if (chr == ' ' || chr == '\n') {}
			else if (chr == '(') res.add(LEFTPAREN);
			else if (chr == ')') res.add(RIGHTPAREN);
			else throw new Exception("Bad character in list string: " + chr);
		}
		if (inkeyword) res.add(new Keyword(string.substring(start)));
		else if (instring) throw new Exception("Missing closing double-quote");
		return res;
	}
	
	/**
	 * Lookup the value for a key in a LispList that has alternating keys and values
	 * @param key
	 * @return
	 */
	public Object getprop(Keyword key) {
		if (key == null) return null;
		int size = this.size();
		for (int i=0; i<size; i+=2) {
			if (key.equals(this.get(i))) {
				return this.get(i+1);
			}
		}
		return null;
	}
	
	/**
	 * Get a property that you know has a String value
	 * @param key
	 * @return (String)this.getprop(key)
	 */
	public String getString(Keyword key) {
		return (String)this.getprop(key);
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
