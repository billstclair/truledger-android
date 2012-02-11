package com.truledger.client;

import java.math.BigInteger;

/**
 * Arbitrary precision decimal arithmetic
 * @author billstclair
 *
 */
public class BCMath {
	/**
	 * The number of digits after the decimal point
	 */
	public int precision = 0;
	
	/**
	 * Default constructor. Initializes precision to 0.
	 */
	public BCMath() {
	}
	
	/**
	 * Constructor when you want a different initial precision
	 * @param precision
	 */
	public BCMath(int precision) {
		this.precision = precision;
	}

	/**
	 * thunk.run() with given precision
	 * @param precision
	 * @param thunk
	 */
	public void withPrecision(int precision, Runnable thunk) {
		if (this.precision == precision) thunk.run();
		else {
			int save = this.precision;
			this.precision = precision;
			try {
				thunk.run();
			} finally {
				this.precision = save;
			}
		}
	}
	
	/**
	 * thunk.run() with given precision
	 * @param precision An integer, encoded as a string in base 10
	 * @param thunk
	 */
	public void withPrecision(String precision, Runnable thunk) {
		this.withPrecision(Integer.valueOf(precision), thunk);
	}
	
	/**
	 * Another name for withPrecision
	 * @param precision
	 * @param thunk
	 */
	public void wbp(int precision, Runnable thunk) {
		this.withPrecision(precision, thunk);
	}
	
	/**
	 * Another name for withPrecision
	 * @param precision
	 * @param thunk
	 */
	public void wbp(String precision, Runnable thunk) {
		this.withPrecision(Integer.valueOf(precision), thunk);
	}
	
	/**
	 * Return the number of digits after the decimal point in number, always 0
	 * @param number
	 * @param rawcell If non-null, rawcell[0] will be set to String.valueOf(number)
	 * @return
	 */
	public static int numberPrecision(int number, String[] rawcell) {
		if (rawcell != null) rawcell[0] = String.valueOf(number);
		return 0;
	}
	
	/**
	 * Always returns 0.
	 * @param number
	 * @return
	 */
	public static int numberPrecision(int number) {
		return 0;
	}
	
	/**
	 * Return the number of digits after the decimal point in number.
	 * @param number
	 * @param rawcell If non-null, rawcell[0] is set to number with the decimal point removed
	 * @return
	 */
	public static int numberPrecision(String number, String[] rawcell) {
		int pos = number.indexOf('.');
		if (pos < 0) {
			if (rawcell != null) rawcell[0] = number;
			return 0;
		}
		rawcell[0] = number.substring(0, pos) + number.substring(pos+1);
		return number.length() - pos - 1;
	}
	
	/**
	 * Return the number of digits after the decimal point in number
	 * @param number
	 * @return
	 */
	public static int numberPrecision(String number) {
		return numberPrecision(number, null);
	}
	
	/**
	 * Return the maximum numberPrecision() for a bunch of numbers
	 * @param numbers
	 * @return
	 */
	public static int maxNumberPrecision(String... numbers) {
		int max = 0;
		for (String number: numbers) max = Math.max(max, numberPrecision(number));
		return max;
	}
	
	/**
	 * Split a number into its integer and decimal parts
	 * @param number The number to split
	 * @param fractionCell If non-null fractionCell[0] is set to the decimal part
	 * @return the integer part of number
	 */
	public static String splitDecimal(String number, String[] fractionCell) {
		int pos = number.indexOf('.');
		if (pos < 0) {
			if (fractionCell != null) fractionCell[0] = "0";
			return number;
		}
		if (fractionCell != null) {
			int len = number.length();
			fractionCell[0] = (len > pos) ? "0." + number.substring(pos+1) : "0";
		}
		return number.substring(0, pos);
	}
	
	/**
	 * Return the integer part of a decimal number
	 * @param number
	 * @return
	 */
	public static String splitDecimal(String number) {
		return splitDecimal(number, null);
	}
	
	/**
	 * Split a number into its integer and decimal parts
	 * @param number
	 * @param fractionCell if non-null, set fractionCell[0] to "0"
	 * @return String.valueOf(number)
	 */
	public static String splitDecimal(int number, String[] fractionCell) {
		if (fractionCell != null) fractionCell[0] = "0";
		return String.valueOf(number);
	}
	
	/**
	 * Add zerocount '0' chars to the end of x
	 * @param x
	 * @param zerocount
	 * @return
	 */
	public static String zeroPad(String x, int zerocount) {
		return zeroPad(x, zerocount, "");
	}
	
	/**
	 * Return prefix + zerocount '0' chars + suffix
	 * @param prefix
	 * @param zerocount
	 * @param suffix
	 * @return
	 */
	public static String zeroPad(String prefix, int zerocount, String suffix) {
		StringBuilder buf = new StringBuilder(prefix.length() + zerocount + suffix.length());
		buf.append(prefix);
		for (int i=0; i<zerocount; i++) buf.append('0');
		buf.append(suffix);
		return buf.toString();
	}
	
	/**
	 * Shift the number in String left by the current precision, truncating if necessary
	 * @param x
	 * @return
	 */
	public BigInteger shiftPrecision(String x) {
		String[] rawcell = new String[1];
		int precision = numberPrecision(x, rawcell);
		String raw = rawcell[0];
		int diff = this.precision - precision;
		String str;
		if (diff > 0) str = zeroPad(raw, diff);
		else if (diff < 0) str = raw.substring(0, raw.length() + diff);
		else str = raw;
		return new BigInteger(str);
	}
	
	/**
	 * Shift x by the current precision
	 * @param x
	 * @return
	 */
	public BigInteger shiftPrecision(int x) {
		BigInteger res = BigInteger.valueOf(x);
		return res.multiply(BigInteger.TEN.pow(this.precision));
	}
	
	/**
	 * Shift an integer string to the right by the current precision
	 * @param x
	 * @return
	 */
	public String unshiftPrecision(String x) {
		if (this.precision == 0) return x;
		int len = x.length();
		if (len>0 && x.charAt(0)=='-') {
			return "-" + this.unshiftPrecision(x.substring(1));
		}
		int diff = len - this.precision;
		if (diff > 0) return x.substring(0, diff) + '.' + x.substring(diff);
		return zeroPad("0.", -diff, x);
	}
	
	/**
	 * Shift x right by the current precision
	 * @param x
	 * @return
	 */
	public String unshiftPrecision(BigInteger x) {
		return this.unshiftPrecision(x.toString());
	}

	/**
	 * Add two numbers, preserving precision
	 * @param x
	 * @param y
	 * @return
	 */
	public String add(String x, String y) {
		return this.unshiftPrecision(this.shiftPrecision(x).add(this.shiftPrecision(y)));
	}
	
	/**
	 * Add a bunch of numbers, preserving precision
	 * @param numbers
	 * @return
	 */
	public String add(String... numbers) {
		int len = numbers.length;
		if (len == 0) this.unshiftPrecision("0");
		BigInteger res = this.shiftPrecision(numbers[0]);
		for (int i=1; i<len; i++) {
			res = res.add(this.shiftPrecision(numbers[i]));
		}
		return this.unshiftPrecision(res);
	}

	/**
	 * Subtract y from x, preserving precision
	 * @param x
	 * @param y
	 * @return
	 */
	public String subtract(String x, String y) {
		return this.unshiftPrecision(this.shiftPrecision(x).subtract(this.shiftPrecision(y)));
	}
	
	/**
	 * Subtract a bunch of numbers, preserving precision
	 * @param numbers
	 * @return
	 */
	public String subtract(String... numbers) {
		int len = numbers.length;
		if (len == 0) this.unshiftPrecision("0");
		BigInteger res = this.shiftPrecision(numbers[0]);
		for (int i=1; i<len; i++) {
			res = res.subtract(this.shiftPrecision(numbers[i]));
		}
		return this.unshiftPrecision(res);
	}
	
	/**
	 * Multiple two numbers, preserving precision
	 * @param x
	 * @param y
	 * @return
	 */
	public String multiply(String x, String  y) {
		BigInteger res = this.shiftPrecision(x);
		res = res.multiply(this.shiftPrecision(y));
		String str = splitDecimal(this.unshiftPrecision(res));
		return this.unshiftPrecision(str);
	}
	
	/**
	 * Multiple an array of numbers, preserving precision
	 * @param numbers
	 * @return
	 */
	public String multiply(String... numbers) {
		int len = numbers.length;
		if (len == 0) return this.add(numbers);
		BigInteger res = this.shiftPrecision(numbers[0]);
		BigInteger divisor = BigInteger.TEN.pow(this.precision);
		for (int i=1; i<len; i++) {
			res = res.multiply(this.shiftPrecision(numbers[i]));
			res = res.divide(divisor);
		}
		return this.unshiftPrecision(res);
	}
	
	/**
	 * Return dividend/divisor, preserving precision
	 * @param dividend
	 * @param divisor
	 * @return
	 */
	public String divide(String dividend, String divisor) {
		BigInteger shifter = BigInteger.TEN.pow(this.precision);
		BigInteger res = this.shiftPrecision(dividend);
		res = res.multiply(shifter).divide(this.shiftPrecision(divisor));
		return this.unshiftPrecision(res);
	}
	
	public int compare(String x, String y) {
		BigInteger diff = this.shiftPrecision(x).subtract(this.shiftPrecision(y));
		return diff.compareTo(BigInteger.ZERO);
	}
	
	/**
	 * True if two numbers are the same, modulo precision
	 * @param x
	 * @param y
	 * @return
	 */
	public boolean equals(String x, String y) {
		return this.compare(x, y) == 0;
	}

	/**
	 * True if x is really zero, ignoring the precision
	 * @param x
	 * @return
	 */
	public static boolean isZero(String x) {
		int len = x.length();
		for (int i=0; i<len; i++) {
			char c = x.charAt(i);
			if (c!='0' && c!='.') return false;
		}
		return true;
	}
	
	/**
	 * Return num ** exp, preserving precision
	 * @param num
	 * @param exp
	 * @return
	 * @throws Exception
	 */
	public String pow(String num, int exp) {
		if (exp < 0) throw new IllegalArgumentException("Only positive integer exponents supported");
		if (exp == 0) return "1";
		BigInteger res = this.shiftPrecision(num).pow(exp);
		int save = this.precision;
		this.precision = save * (exp - 1);
		try {
			String str = splitDecimal(this.unshiftPrecision(res), null);
			res = new BigInteger(str);
		} finally {
			this.precision = save;
		}
		return this.unshiftPrecision(res);
	}
}

//////////////////////////////////////////////////////////////////////
///
/// Copyright 2012 Bill St. Clair
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

