package com.truledger.client;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Stack;

public class LispList extends ArrayList<Object> {
	/**
	 * A lisp-like interned keyword
	 * @author Bill St. Clair
	 */
	public static class Keyword {
		private String namestring;
		public Keyword(String namestring) {
			this.namestring = namestring;
		}
		public String getNamestring() {
			return namestring;
		}
		public String toString() {
			return ":" + namestring;
		}
	}

	private static final HashMap<String, Keyword> keywordHash = new HashMap<String, Keyword>();

	/**
	 * Intern a string into a keyword
	 * @param namestring
	 * @return
	 */
	public static Keyword internKeyword(String namestring) {
		Keyword res = keywordHash.get(namestring);
		if (res != null) return res;
		return keywordHash.put(namestring,  new Keyword(namestring));
	}

	private static final long serialVersionUID = -7322719017873541150L;

	public LispList() {
		super();
	}

	public LispList(int size) {
		super(size);
	}

	public static LispList valueOf(Object[] array) {
		LispList res = new LispList(array.length);
		res.add(array);
		return res;
	}

	public String toString() {
		StringBuilder res = new StringBuilder();
		this.toStringBuf(new StringBuilder());
		return res.toString();
	}

	public void toStringBuf(StringBuilder res) {
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
				((LispList)elt).toStringBuf(res);
			} else {
				throw new Error("Only strings, keywords, and Lists supported");
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
			} else if (tok == RIGHTPAREN) {
				if (stack.size() == 0) {
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
				} else if (chr == '\\') {
					escaped = true;
					buf.append(string.substring(start, i));
					start = i+1;
				}
			} else if (inkeyword) {
				if (" :\n\"".indexOf(chr) >= 0) {
					res.add(new Keyword(string.substring(start, i)));
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
}
