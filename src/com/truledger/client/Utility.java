package com.truledger.client;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Vector;

import org.spongycastle.util.encoders.Base64;

public class Utility {
  public static String bin2hex(int bin) {
	  return bin2hex(BigInteger.valueOf(bin));
  }
  
  public static String bin2hex(BigInteger bin) {
	  String s = bin.toString(16);
	  return (s.length() % 2 == 0) ? s : "0" + s;  
  }
  
  final private static String[] pairs =
	  {"00","01","02","03","04","05","06","07","08","09","0a","0b","0c","0d","0e","0f",
	   "10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f",
	   "20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f",
	   "30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f",
	   "40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f",
	   "50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f",
	   "60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f",
	   "70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f",
	   "80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f",
	   "90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f",
	   "a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af",
	   "b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf",
	   "c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf",
	   "d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df",
	   "e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef",
	   "f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe","ff"};

  public static String bin2hex(byte buf[]) {
	  StringBuffer out = new StringBuffer(2*buf.length);
	  for (int b : buf) {
		  if (b < 0) b += 256;
		  out.append(pairs[b]);
	  }
	  return out.toString();
  }
  
  public static int hexcode2int(int hexcode) {
	  if (hexcode>=(int)'0' && hexcode<=(int)'9') return hexcode - (int)'0';
	  else if (hexcode>=(int)'a' && hexcode<=(int)'f') return hexcode - (int)'a' + 10;
	  else if (hexcode>=(int)'A' && hexcode<=(int)'F') return hexcode - (int)'A' + 10;
	  else return 0;
  }
  
  public static String hex2bin(String hex) {
	  byte[] hexbuf = hex.getBytes();
	  int len = hexbuf.length;
	  StringBuilder buf = new StringBuilder(len/2);
	  for (int i=0; i<len; i+=2) {
		  int b0 = hexbuf[i];
		  int b1 = hexbuf[i+1];
		  buf.append((char)(hexcode2int(b0)<<4 + hexcode2int(b1)));
	  }
	  return buf.toString();
  }
  
  public static String base64Encode(byte buf[], int columns) {
	  byte[] buf64 = Base64.encode(buf);
	  int len = buf64.length;
	  int newlines = (columns == 0) ? 0 : (len - 1) / columns;
	  if (newlines == 0) columns = len+1;
	  char[] chars = new char[len + newlines];
	  int linecnt = columns;
	  int j = 0;
	  for (int i=0; i<len; i++) {
		  if (linecnt == 0) {
			  chars[j++] = '\n';
			  linecnt = columns;
		  }
		  chars[j++] = (char)buf64[i];
		  linecnt--;
	  }
	  return String.valueOf(chars);
  }
  
  public static String base64Encode(byte buf[]) {
	  return base64Encode(buf, 64);
  }

  public static byte[] base64Decode(String string) {
	  return Base64.decode(string);
  }

  public static byte[] base64Decode(byte buf[]) {
	  return Base64.decode(buf);
  }
  
  public static boolean isBlank(String x) {
	  return x == null || x.equals("");
  }
  
  /**
   * Return the substring of str that begins with pattern
   * @param str
   * @param pattern
   * @return substring of str beginning with pattern or NULL
   */
  public static String strstr(String str, String pattern) {
	  int pos = str.indexOf(pattern);
	  return (pos >= 0) ? str.substring(pos) : null;
  }
  
  public static boolean isHexChar(char chr) {
	  int code = (int)chr;
	  return (code>=(int)'0' && code<=(int)'9') ||
			 (code>=(int)'a' && code<=(int)'f') ||
			 (code>=(int)'A' && code<=(int)'F');
  }
  
  public static boolean isCouponNumber(String couponNumber) {
	  if (couponNumber == null) return false;
	  int len = couponNumber.length();
	  if (len != 40) return false;
	  for (int i=0; i<len; i++) {
		  if (!isHexChar(couponNumber.charAt(i))) return false;
	  }
	  return true;	  
  }
  
  public static String xorSalt(String string, String salt) {
	  if (isBlank(salt)) return string;
	  int strlen = string.length();
	  int saltlen = salt.length();
	  char[] buf = new char[strlen];
	  int idx = 0;
	  for (int i=0; i<strlen; i++) {
		  buf[i] = salt.charAt(idx);
		  if (++idx >= saltlen) idx = 0;
	  }
	  return xorStrings(string, salt);
  }
  
  public static String xorStrings(String s1, String s2) {
	  int s1len = s1.length();
	  int s2len = s2.length();
	  int maxlen = Math.max(s1len, s2len);
	  char[] buf = new char[maxlen];
	  int minlen = Math.min(s1len,  s2len);
	  for (int i=0; i<minlen; i++) {
		  buf[i] = (char)((int)s1.charAt(i) ^ (int)s2.charAt(i));
	  }
	  String tail = (s1len >= s2len) ? s1 : s2;
	  for (int i=minlen; i<maxlen; i++) {
		  buf[i] = tail.charAt(i);
	  }
	  return tail.toString();
  }
  
  /**
   * Compare two, possibly null strings.
   * null is considered less than non-null
   * @param s1
   * @param s2
   * @return -1, 0, 1 according to s1 < s2, s1 == s2, s1 > s2
   */
  public static int compareStrings(String s1, String s2) {
	  if (s1 == null) {
		  return (s2 == null) ? 0 : -1;
	  } else if (s2 == null) return 1;
	  return s1.compareTo(s2);
  }

  /**
   * Explode a string at a separator
   * @param separator The separator character
   * @param string A string
   * @return A list of the substrings of string around the separator
   */
  public static String[] explode(char separator, String string) {
	  if (string == null) return null;
	  int len = string.length();
	  int start = 0;
	  int end;
	  ArrayList<String> res = new ArrayList<String>(5);
	  while (start < len) {
		  end = string.indexOf(separator, start);
		  if (end < 0) end = len;
		  res.add(string.substring(start, end));
		  start = end + 1;
	  }
	  return res.toArray(new String[res.size()]);
  }
  
  /**
   * Append strings with a separator between them
   * @param separator
   * @param strings
   * @return
   */
  public static String implode(char separator, String[] strings) {
	  if (strings == null) return "";
	  int len = -1;
	  for (String string: strings) len += string.length() + 1;
	  StringBuilder buf = new StringBuilder(len);
	  boolean first = true;
	  for (String string: strings) {
		  if (first) first = false;
		  else buf.append(separator);
		  buf.append(string);
	  }
	  return buf.toString();
  }
  
  /**
   * Append addedString to strings with separator between each element.
   * @param separator
   * @param addedString
   * @param strings
   * @return
   */
  public static String implode(char separator, String addedString, String[] strings) {
	  if (strings == null) return addedString;
	  int len = addedString.length();
	  for (String string: strings) len += string.length() + 1;
	  StringBuilder buf = new StringBuilder(len);
	  buf.append(addedString);
	  for (String string: strings) {
		  buf.append(separator);
		  buf.append(string);
	  }
	  return buf.toString();
  }
  
  /**
   * @param needle string to search for
   * @param haystack array of strings in which to search
   * @return index of needle in haystack, or -1 if not found
   */
  public static int position(String needle, String[] haystack) {
	  for (int i=0; i<haystack.length; i++) {
		  if (needle.equals(haystack[i])) return i;
	  }
	  return -1;
  }
  
  /**
   * Escape characters in a string
   * @param string The string to escape
   * @param escape The escape character
   * @param charsToEscape The output will have the escape character in front of these characters and itself
   * @return
   */
  public static String escapeString(String string, char escape, String charsToEscape) {
	  int len = string.length();
	  StringBuilder res = new StringBuilder(len + 5);
	  escapeStringToBuf(string, escape, charsToEscape, res);
	  return res.length()==len ? string : res.toString();
  }

  /**
   * Write string to buf escaping charsToEscape & escape with escape
   * @param string
   * @param escape
   * @param charsToEscape
   * @param buf
   */
  public static void escapeStringToBuf(String string, char escape, String charsToEscape, StringBuilder buf) {
	  int len = string.length();
	  for (int i=0; i<len; i++) {
		  char chr = string.charAt(i);
		  if (chr==escape || charsToEscape.indexOf(chr) >= 0) buf.append(escape);
		  buf.append(chr);
	  }
  }
  
  /** 
   * "Return the id for an asset"
   * @param id
   * @param scale
   * @param precision
   * @param assetname
   * @return
   */
  public static String assetid(String id, String scale, String precision, String assetname) {
	  return Crypto.sha1(id + ',' + scale + ',' + precision + ',' + assetname);
  }
  
  /**
   * @param chr
   * @return True if chr is lowercase or uppercase a to z or 0 to 9
   */
  public static boolean isAlphanumeric(char chr) {
	  return ('0'<=chr && chr<='9') || ('a'<=chr && chr<='z') || ('A'<=chr && chr<='Z');
  }
  
  /**
   * @param chr
   * @return true if chr isAlphanumeric() or a space
   */
  public static boolean isAlphanumericOrSpace(char chr) {
	  return chr==' ' || isAlphanumeric(chr);
  }
  
  /**
   * @param str
   * @param integerToo
   * @return true if str is a numeric string. If integerToo is true, it must be an integer string
   */
  public static boolean isNumeric(String str, boolean integerToo) {
	  boolean sawdot = integerToo;
	  int len = str.length();
	  for (int i=0; i<len; i++) {
		  char chr = str.charAt(i);
		  if (chr == '-') {
			  if (i > 0) return false;
		  } else if (chr == '.') {
			  if (sawdot) return false;
			  sawdot = true;
		  } else {
			  if ('0' > chr || chr > '9') return false;
		  }
	  }
	  return true;
  }
  
  /**
   * @param str
   * @return true if str is a numeric string
   */
  public static boolean isNumeric(String str) {
	  return isNumeric(str, false);
  }
  
  /**
   * @param acct
   * @return If acct is a valid account name string, i.e. every character isAlphanumeric()
   */
  public static boolean isAcctName(String acct) {
	  int len = acct.length();
	  for (int i=0; i<len; i++) {
		  if (!isAlphanumeric(acct.charAt(i))) return false;
	  }
	  return true;
  }
  
  /**
   * Add together balance and fractionBuf[0], to digits precision.
   * Return the resulting balance. Store the fractional part in fractionBuf[0];
   * @param balance
   * @param fractionBuf
   * @param digits
   * @return
   */
  public static String normalizeBalance(String balance, String[] fractionBuf, int digits) {
	  BCMath bcm = new BCMath(digits);
	  return BCMath.splitDecimal(bcm.add(balance, fractionBuf[0]), fractionBuf);
  }
  
  /**
   * Return the number of digits to use to track fractional balances for an asset with a storage fee of percent
   * @param percent
   * @return
   */
  public static int fractionDigits(String percent) {
	  return BCMath.numberPrecision(percent) + 8;
  }
  
  /**
   * Split string at delim
   * @param delim
   * @param string
   * @return
   */
  public static String[] splitString(char delim, String string) {
	  Vector<String> res = new Vector<String>();
	  int len = string.length();
	  int start = 0;
	  for (int i=0; i<len; i++) {
		  if (string.charAt(i) == delim) {
			  res.add(string.substring(start, i));
			  start = i+1;
		  }
	  }
	  res.add(start==len ? "" : string.substring(start));
	  return res.toArray(new String[res.size()]);
  }
  
  /**
   * Seconds per year times 100
   */
  public static final String secsPerYearPct = BCMath.sMultiply(String.valueOf(60 * 60 * 24 * 365), "100");
  
  /**
   * Compute the storage fee of balanceBuf[0] with the given percent, for now-baltime, and percent digits
   * Return the fee as the function value. Store balance - fee in balanceBuf[0]
   * @param balanceBuf a one-element array containing the balance. Decremented by the returned fee
   * @param baltime the time of the balance
   * @param now the time now
   * @param percent the fee percent
   * @param digits the precision digits for the fee percent
   * @return
   */
  public static String storageFee(String[]balanceBuf, String baltime, String now, String percent, int digits) {
	  String balance = balanceBuf[0];
	  BCMath bcm = new BCMath(digits);
	  if (bcm.compare(percent, "0") == 0) return "0";
	  String fee = bcm.divide(bcm.multiply(balance, percent, BCMath.sSubtract(now, baltime)), secsPerYearPct);
	  if (bcm.compare(fee,  "0") < 0) fee = "0";
	  else if (bcm.compare(fee, balance) > 0) fee = balance;
	  balanceBuf[0] = bcm.subtract(balance, fee);
	  return fee;
  }
  
  /**
   * Parse a string of the form "[x,y,...,z]" into an array of strings: new String[]{x, y, ..., z}
   * @param string
   * @return
   * @throws Exception
   */
  public static String[] parseSquareBracketString(String string) throws Exception {
	  string = string.trim(); 
	  Vector<String> res = new Vector<String>();
	  int len = string.length();
	  if (len==0 || string.charAt(0)!='[') {
		  throw new Exception("First non-whitespace char not opening square bracket");
	  }
	  boolean escaped = false;
	  int start = 1;
	  for (int i=1; i<len; i++) {
		  if (escaped) {
			  escaped = false;
			  continue;
		  }
		  char chr = string.charAt(i);
		  if (chr == '\\') escaped = true;
		  else if (chr == ',') {
			  res.add(string.substring(start, i));
			  start = i+1;
		  } else if (chr == ']') {
			  if (i != (len-1)) throw new Exception("Non-whitespace character after closing square bracket");
			  res.add(string.substring(start, i));
			  return res.toArray(new String[res.size()]);
		  }
	  }
	  throw new Exception("No closing square bracket");
  }
  
/*
    (loop
       (when (>= i len) (error "No closing square bracket"))
       (let ((char (aref string i)))
         (incf i)
         (cond (esc-p
                (write-char char stream)
                (setf esc-p nil))
               ((eql char #\\)
                (setf esc-p t))
               ((eql char #\,)
                (push (get-output-stream-string stream) res))
               ((eql char #\])
                (push (get-output-stream-string stream) res)
                (return))
               (t (write-char char stream)))))
    ;; Ensure nothing but whitespace at end
    (loop
       (when (>= i len) (return))
       (unless (member (aref string i) *whitespace*)
         (error "Non-whitespace character after closing square bracket"))
       (incf i))
    (nreverse res)))
 */
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
