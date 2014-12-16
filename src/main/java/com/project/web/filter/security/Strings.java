/*
* MONITISE CONFIDENTIAL
* ____________________
*
* Copyright 2003 - 2012 Monitise Group Limited
* All Rights Reserved. www.monitisegroup.com
*
* NOTICE: All information contained herein is, and remains
* the property of Monitise Group Limited or its group
* companies. The intellectual and technical concepts contained
* herein are proprietary to Monitise Group Limited and Monitise
* group companies and may be covered by U.S. and
* Foreign Patents, patents in process, and are protected by
* trade secret or copyright law. Dissemination of this information
* or reproduction of this material is strictly forbidden unless prior
* written permission is obtained from Monitise Group Limited. Any
* reproduction of this material must contain this notice
*
*/
package com.project.web.filter.security;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author phillip.fitzsimmons
 *
 * Convenience methods for manipulating Strings, largely
 * lifted from examples on the net.
 */
public abstract class Strings {
	private static final int BLOCK_SIZE = 8;
	private static final int RADIX_HEX = 16;
	private static final double KB = 1000.0;
	private static final double MB = 1000000.0;

	/** Empty String */
	public static final String EMPTY = "";

	private static final byte MAC_PAD_CHARACTER = (byte) 'F';

	/**
	 * Joins an array of strings into a string using a delimiter.
	 *
	 * @param array the array of strings.
	 * @param delim the delimiter.
	 * @return the corresponding string.
	 */
	public static String join(String[] array, char delim) {
		return join(array, String.valueOf(delim));
	}
	/**
	 * Joins an array of Objects into a string using a delimiter.
	 * Converts the object to a String.
	 *
	 * @param array the array of strings.
	 * @param delim the delimiter.
	 * @return the corresponding string.
	 */
	public static String join(Object[] array, char delim) {
		String[] stringArray = new String[array.length];
		for (int i = 0; i < array.length; i++) {
			stringArray[i] = array[i].toString();
		}
		return join(stringArray, String.valueOf(delim));
	}

	/**
	 * Join to array as a String
	 *
	 * @param array the array
	 * @param delim the delimeter of the array elements
	 * @return the joined String
	 */
	public static String join(Object[] array, String delim) {
		String[] stringArray = new String[array.length];
		for (int i = 0; i < array.length; i++) {
			stringArray[i] = array[i].toString();
		}
		return join(stringArray, String.valueOf(delim));
	}

	/**
	 * Joins an array of strings into a string using a delimiter.
	 *
	 * @param array the array of strings.
	 * @param delim the delimiter.
	 * @return the corresponding string.
	 */
	public static String join(String[] array, String delim) {
		switch (array.length) {
			case 0 :
				return Strings.EMPTY;
			case 1 :
				return array[0];
			default :
				StringBuffer buffer = new StringBuffer();
				buffer.append(array[0]);
				for (int i = 1; i < array.length; i++) {
					buffer.append(delim);
					buffer.append(array[i]);
				}
				return buffer.toString();
		}
	}
	/**
	 * Joins Collection into a string using a delimiter.
	 *
	 * @param collection The Collection to be joined.
	 * @param delim the delimiter.
	 * @return the corresponding string.
	 */
	public static String join(Collection<?> collection, String delim) {
		Object[] array = collection.toArray();
		switch (array.length) {
			case 0 :
				return Strings.EMPTY;
			case 1 :
				return array[0].toString();
			default :
				StringBuffer buffer = new StringBuffer();
				buffer.append(array[0]);
				for (int i = 1; i < array.length; i++) {
					buffer.append(delim);
					buffer.append(array[i].toString());
				}
				return buffer.toString();
		}
	}
	/**
	 * Breaks a string into an array of strings around a delimiter.
	 *
	 * @param str the string.
	 * @param delim the delimiter.
	 * @return the corresponding array of strings.
	 */
	public static String[] split(String str, char delim) {
		return split(str, String.valueOf(delim));
	}

	/**
	 * Breaks a string into an array of strings around a delimiter.
	 *
	 * @param str the string.
	 * @param delim the delimiter.
	 * @return the corresponding array of strings.
	 */
	public static String[] split(String str, String delim) {

		/*
		 * A string tokenizer is not used because it ignores consecutive
		 * delimiters.
		 */
		int len = delim.length();
		List<String> result = new ArrayList<String>();
		while (true) {
			int pos = str.indexOf(delim);
			if (pos < 0) {
				result.add(str);
				break;
			} else {
				result.add(str.substring(0, pos));
				str = str.substring(pos + len);
			}
		}
		return result.toArray(new String[0]);
	}

	/**
	 * Counts the number of occurences of a substring in a string.
	 *
	 * @param s the string.
	 * @param sub the substring.
	 * @return the number of occurences.
	 */
	public static int occur(String s, String sub) {
		int occur = 0;
		while (true) {
			int index = s.indexOf(sub);
			if (index < 0) {
				return occur;
			}
			occur++;
			s = s.substring(index + sub.length());
		}
	}

	/**
	 * Strip off all the xml tags from the String and returns the result as a
	 * String. Tags will be between '<' and '>'
	 *
	 * @param str String to strip
	 * @return stripped String
	 */
	public static String stripOffTags(String str) {
		while (true) {
			int start = str.indexOf("<");
			if (start < 0) {
				break;
			} else {
				int end = str.indexOf(">", start);
				if ((start > 0) && (end < 0)) {
					break;
				} else {
					str = str.substring(0, start) + str.substring(end + 1);
				}
			}
		}
		return str;
	}

	/**
	 * Strip off all the unicodes from the String and returns the result as a
	 * String. Unicode chars will be between '&' and ';'.
	 *
	 * @param str String to strip
	 * @return stripped String
	 */
	public static String stripOffUnicodes(String str) {
		while (true) {
			int start = str.indexOf("&");
			if (start < 0) {
				break;
			} else {
				int end = str.indexOf(";", start);
				if ((start > 0) && (end < 0)) {
					break;
				} else {
					str = str.substring(0, start) + str.substring(end + 1);
				}
			}
		}
		return str;
	}

	/**
	 * Convenient method as to use both stripOffUnicodes and stripOffTags methods
	 *
	 * @param str String to strip tags an unicodes from
	 * @return the stripped Stringg
	 */
	public static String stripOffUnicodeAndTags(String str) {
		return stripOffUnicodes(stripOffTags(str));
	}

	/**
	 * Converts Object[] to a String[]
	 *
	 * @param obj Object array
	 * @return String[]
	 */
	public static String[] convertToStringArray(Object[] obj) {
		String[] returnStrArray = new String[obj.length];
		for (int i = 0; i < obj.length; i++) {
			returnStrArray[i] = (String) obj[i];
		}
		return returnStrArray;
	}

	/**
	 * Format the given long representing a file size in a String format
	 * @param size the size in bytes
	 * @return the formatted size
	 */
	public static String formatFileSize(long size) {
		String sizeStr = null;
		if (size <= 0) {
			sizeStr = "0";
		} else {
			Object[] msgArgs = new Object[1];
			MessageFormat mf = new MessageFormat("{0,number,#,##0.00}");
			double sizeDbl = size;
			if (sizeDbl < KB) {
				sizeStr = size + " Bytes";
			} else if (sizeDbl < MB) {
				msgArgs[0] = new Double(sizeDbl / KB);
				sizeStr = mf.format(msgArgs) + " kB";
			} else {
				msgArgs[0] = new Double(sizeDbl / MB);
				sizeStr = mf.format(msgArgs) + " MB";
			}
		}
		return sizeStr;
	}

	/**
	 *
	 * @param str the String in which substrings have to be replaced
	 * @param oldString : the substring which has to be replaced
	 * @param newString : the new value of the substring
	 * @return String the String which was passed, with old values replaced by
	 * new ones
	 */
	public static String replace(
		String str,
		String oldString,
		String newString) {

		for (int i = str.indexOf(oldString);
			i < str.length();
			i = str.indexOf(oldString, i + newString.length())) {
			if (i < 0) {
				break;
			}
			str = str.substring(0, i) + newString + str.substring(i + 1);
		}
		return str;
	}

	/**
	 * Replace unescaped SQL quotes, with escaped quotes, e.g. ' > ''
	 * @param str String to replace quotes in
	 * @return str with replaced quotes
	 */
	public static String escapeSpecialSQLCharacters(String str) {
		return Strings.replace(str, "'", "''");
	}

	/**
	 * Get the Date defined by calendar in a short date format
	 * @param calendar date to format
	 * @return the formatted date
	 */
	public static String shortDateFormat(Calendar calendar) {
		return DateFormat.getDateInstance(DateFormat.SHORT).format(calendar.getTime());
	}

	/**
	 * Get the Date defined by calendar in a full date format
	 * @param calendar date to format
	 * @return the formatted date
	 */
	public static String fullDateFormat(Calendar calendar) {
		return DateFormat.getDateInstance(DateFormat.FULL).format(calendar.getTime());
	}

	/**
	 * Get the Date defined by calendar in a medium date format
	 * @param calendar date to format
	 * @return the formatted date
	 */
	public static String mediumDateFormat(Calendar calendar) {
		return DateFormat.getDateInstance(DateFormat.MEDIUM).format(calendar.getTime());
	}

	/**
     * Translates a string into <code>x-www-form-urlencoded</code>
     * format. This method uses the platform's default encoding
     * as the encoding scheme to obtain the bytes for unsafe characters.
     *
     * @param   s   <code>String</code> to be translated.
     * @deprecated The resulting string may vary depending on the platform's
     *             default encoding. Instead, use the encode(String,String)
     *             method to specify the encoding.
     * @return  the translated <code>String</code>.
	 * @throws java.io.UnsupportedEncodingException
	 */
	@Deprecated
	public static String urlEncoder(String s) {
		if (s == null) {
			return null;
		}
		return URLEncoder.encode(s);
	}

	/**
	 * Encodes the url using an encoding format
	 *
	 * @deprecated Instead use the <code>urlUTF8Encoder</code> method of <code>URLUtil</code>
	 * @param s String to encode
	 * @param enc encoding format
	 * @return the encoded String
	 * @throws java.io.UnsupportedEncodingException if enc in invalid
	 */
	@Deprecated
	public static String urlEncoder(String s, String enc) throws UnsupportedEncodingException {
		if (s == null) {
			return null;
		}
		return URLEncoder.encode(s, enc);
	}

	/**
	 * Decodes an UTF8 encoded string
	 *
	 * @param string String to encode
	 * @return encoded String
	 * @throws java.io.UnsupportedEncodingException UTF encoding is not supported
	 */
	public static String urlDecoder(String string) throws UnsupportedEncodingException {

		if (null == string) {
			return null;
		}

		return URLDecoder.decode(string, "utf8");
	}

	/**
	 * Encodes a string used in CAN Mailer file required format
	 *
	 * @param s String to encode
	 * @return encoded String
	 */
	public static String textXmlEncoder(String s) {
		if (s == null) {
			return s;
		}

		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c == '&') {
				sb.append("&amp;");
			} else if (c == '<') {
				sb.append("&lt;");
			} else if (c == '>') {
				sb.append("&gt;");
			} else if (c == '"') {
				sb.append("&quot;");
			} else if (c == '\'') {
				sb.append("&apos;");
			} else {
				sb.append(c);
			}
		}
		return sb.toString();
	}

	/**
	 * Encodes a string using old MATML encoding
	 *
	 * @deprecated Instead use the urlUTF8Encoder method of <code>URLUtil</code>
	 * @param s String to encode
	 * @return encoded String
	 */
	@Deprecated
	public static String textEncoder(String s) {
		 if (s == null) {
			return s;
		}

		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c == '&') {
				sb.append("&amp;");
			} else if (c == '<') {
				sb.append("&lt;");
			} else if (c == '>') {
				sb.append("&gt;");
			} else if (c == '"') {
				sb.append("&quot;");
			} else if (c == '\'') {
				sb.append("%27");
			} else if (c == '+') {
				sb.append("%2B");
			} else if (c == '%') {
				sb.append("%25");
			} else {
				sb.append(c);
			}
		}
		return sb.toString();
	}

	private static final int EXPANDED_LENGTH_MULTIPLIER = 3;
	private static final int LAST_CONTROL_CHARACTER = 15;
	/**
	 * @deprecated Instead use the <code>urlUTF8Encoder</code> method of
	 *             <code>URLUtil</code>
	 * @param s String to encode
	 * @return Encoded Str
	 */
	@Deprecated
	public static String matmlUrlEncoder(String s) {
		if (s == null) {
			return s;
		}
		StringBuilder sb = new StringBuilder(s.length() * EXPANDED_LENGTH_MULTIPLIER);
		try {
			char c;
			for (int i = 0; i < s.length(); i++) {
				c = s.charAt(i);
				if (c == '&') {
					sb.append("&amp;");
				} else if (c == ' ') {
					sb.append('+');
				} else if ((c >= ',' && c <= ';') || (c >= 'A' && c <= 'Z')
						|| (c >= 'a' && c <= 'z') || c == '_' || c == '?') {
					sb.append(c);
				} else {
					sb.append('%');
					if (c > LAST_CONTROL_CHARACTER) { // is it a non-control char, ie. >x0F so 2
									// chars
						sb.append(Integer.toHexString(c)); // just add %
																// and the
																// string
					} else {
						sb.append("0")
						.append(Integer.toHexString(c));
						// otherwise need to add a leading 0
					}
				}
			}

		} catch (Exception ex) {
			return (s);
		}
		return (sb.toString());
	}

	/** Left direction, used in pad method */
	public static final int DIRECTION_LEFT = 0;
	/** Right direction, used in pad method */
	public static final int DIRECTION_RIGHT = 1;

	/**
	 * Pad the given string, with character in the given direction until it is the given length
	 * @param string String to pad
	 * @param character character to pad with
	 * @param direction direction to pad (0 = left, 1 = right)
	 * @param length length to pad to
	 * @return the padded String
	 */
	public static String pad(String string, char character, int direction, int length) {
		if (string == null) {
			string = Strings.EMPTY;
		}
		if (string.length() > length) {
			return string;
		}
		length = length - string.length();
		for (int i = 0; i < length; i++) {
			switch (direction) {
			case DIRECTION_LEFT: {
				string = character + string;
				break;
			}
			case DIRECTION_RIGHT: {
				string += character;
				break;
			}
			default:
			}
		}
		return string;
	}

	private static final int LAST_4_DIGITS = 4;

	/**
	 * Replaces the string with '*' for each digit except the last 4 digits This
	 * is useful for hiding a PAN or any other sensitive data.  If the string
	 * is less than 4 characters the whole string will be displayed.
	 *
	 * @param string the string to mask
	 * @return the masked string
	 */
	public static String hide(String string) {
		return hide(string, Math.min(LAST_4_DIGITS, string != null ? string.length() : 0), '*');
	}

	/**
	 * Improved PAN obfuscate utility method. Instead of replacing the whole string
	 * with a mask text, this method hides obfuscates any string found which matches
	 * the provided regex rules using the original "hide" method.
	 *
	 * @param output the text to search and obfuscate any matching text.
	 * @param rules the regex rules used to match.
	 * @return the masked output according to the rules
	 */
	public static String hidePanInDebugOutput(String output, String rules) {
		// Returns a Pattern object
		Pattern pattern = Pattern.compile(rules);

		// Get the handle for matcher
		Matcher matcher = pattern.matcher(output);

		while (matcher.find()) {
			// Replace the all sequence of numbers by * symbol except last 4
			String group = matcher.group();
			if (matcher.groupCount() > 0) {
				group = matcher.group(1);
			}
			String obfuscatedGroup = hide(group);
			output = output.replace(group, obfuscatedGroup);
		}

		// Return result
		return output;
	}

	/**
	 * This method is designed to replace elements in the original string,
	 * with the hidden char value passed in, leaving only the characters
	 * <br>
	 * For exmaple with a bank card number, <code>0000304903401234567</code>
	 * we would ideally like it to be displayed
	 * <code></code> for security reasons. Therefore in this
	 * case we set the <code>displayRemaining</code> as <b>4</b> and the
	 * <code>hiddenvalue</code> as <b>*</b>. Thus the result is
	 * <code>***************4567</code>
	 *
	 * @param string The original String to hide
	 * @param displayRemaining the number of characters from the right to leave.
	 * @param hiddenvalue the replacement character
	 * @return an empty string ("") if the <code>String</code> is <code>null</code> or empty,
	 *         otherwise the hidden <code>String</code> value
	 */
	public static String hide(String string, int displayRemaining, char hiddenvalue) {
		if (string == null || string.length() == 0) {
			return Strings.EMPTY;
		} else if (displayRemaining > string.length()) {
			throw new IllegalArgumentException("Please ensure that the displayRemaining value "
					+ "is smaller than the original String length");
		} else {
			int range = (string.length() - displayRemaining);
			char[] hide = new char[range];
			for (int i = 0; i < range; i++) {
				hide[i] = hiddenvalue;
			}
			return new String(hide) + string.substring(range, string.length());
		}
	}

	/**
	 * Checks whether the given input string is number/numeric.
	 *
	 * @param text the text
	 * @return true when the given text represents a number
	 */
	public static boolean isNumber(String text) {
		if (null == text) {
			return false;
		}
		char[] chars = text.toCharArray();
		if (chars.length == 0) {
			return false;
		}

		for (int i = 0; i < chars.length; i++) {
			char c = chars[i];
			if (Character.isDigit(c)) {
				continue;
			} else {
				return false;
			}
		}
		return true;
	}

	/**
	 * Convert a String to a byte array. For example if the input buffer
	 * contains { '1', '2', '3, '4', 'a', '5'} this method will return
	 * {(byte)0x12, (byte)0x34, (byte)0xa5}.
	 *
	 * @param in String to be converted to a byte array.
	 * @return Generated byte array
	 */
	public static byte[] hexStringToByteArray(String in) {
		int iOutputLen = in.length() / 2;
		byte[] bytesOutput = new byte[iOutputLen];
		Strings.hexStringToByteArray(in, bytesOutput);
		return bytesOutput;
	}

	/**
	 * Convert a String to a byte array. For example if the input buffer
	 * contains { '1', '2', '3, '4', 'a', '5'} this method will return
	 * {(byte)0x12, (byte)0x34, (byte)0xa5}.
	 *
	 * @param in String to be converted to a byte array.
	 * @param out byte array to fill with result.
	 * @return length of generated byte array
	 */
	public static int hexStringToByteArray(String in, byte[] out) {
		int iOutputLen = in.length() / 2;

		for (int index = 0, i = 0; index < iOutputLen; index++, i = i + 2) {
			String s = in.substring(i, i + 2);
			out[index] = (byte)(Integer.parseInt(s, RADIX_HEX));
		}

		return iOutputLen;
	}

	/**
	 * Convert a byte array into a string format eg byte[]{(byte)0x01, (byte)0x23}
	 * will be represented by the string "0123".
	 *
	 * @param b byte array to be converted to a string representation.
	 * @return String representation of byte array
	 */
	public static String byteArrayToHexString(byte[] b) {
		if (null == b) {
			return "<null>";
		}

		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < b.length; i++) {
			String s = Integer.toHexString(b[i]).toUpperCase();
			int len = s.length();
			if (len == 0) {
				s = "00";
			} else if (len == 1) {
				s = "0" + s;
			} else {
				s = s.substring(len - 2, len);
			}
			sb.append(s);
		}
		return sb.toString();
	}

	/**
	 * Pads the given data with the speficied character upto the specified length on the specified side.
	 * @param str - the data to pad
	 * @param c - the character to pad with
	 * @param maxLength - the length to pad to
	 * @param left - true to pad before the data
	 * 				 false to pad after the data
	 * @return the padded data
	 */
	public static String pad(
		String str,
		char c,
		int maxLength,
		boolean left) {

		if (str == null) {
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < maxLength; i++) {
				sb.append(c);
			}
			return sb.toString();
		}
		int length = str.length();
		if (length == maxLength) {
			return str;
		}
		StringBuffer sb = new StringBuffer(str);
		for (int i = 0; i < maxLength - length; i++) {
			if (left) {
				sb.insert(0, c);
			} else {
				sb.append(c);
			}
		}
		return sb.toString();
	}

	/**
	 * Pad alphanumeric fields
	 *
	 * @param str field
	 * @param maxLength maximum field length
	 * @return the padded field
	 */
	public static String padAlphanumeric(String str, int maxLength) {
		return pad(str, ' ', maxLength, false);
	}

	/**
	 * Pad numeric fields
	 *
	 * @param str field
	 * @param maxLength maximum field length
	 * @return the padded field
	 */
	public static String padNumeric(String str, int maxLength) {
		return pad(str, '0', maxLength, true);
	}

	/**
	 * Strip numeric fields
	 *
	 * @param str field
	 * @return the padded field
	 */
	public static String stripNumeric(String str) {
		// For through each character...
		for (int i = 0; i < str.length(); i++) {
			// If it is a leading 0...
			if (str.charAt(i) != '0') {
				// Delete it...
				str = str.substring(i);
				break;
			}
		}
		// Return remaining string.
		return str;
	}

	/**
	 * Sanitise a string to include it in a LOG entry.
	 * A function call could result in a log forging attack.
	 * Writing unsanitised user-supplied data into a log file allows
	 * an attacker to forge log entries or inject malicious content
	 * into log files. Corrupted log files can be used to cover an
	 * attacker's tracks or as a delivery mechanism for an attack on
	 * a log viewing or processing utility. For example, if a web
	 * administrator uses a browser-based utility to review logs,
	 * a cross-site scripting attack might be possible.
	 *
	 * @param str the string to sanitise.
	 * @return the sanitised string.
	 */
	public static String sanitiseForLogs(String str) {
		return str == null ? null : str.replaceAll("[\n\r]", "");
	}

	/**
	 * Pad binary fields
	 *
	 * @param str field
	 * @param maxLength maximum field length
	 * @return the padded field
	 */
	public static String padBinary(String str, int maxLength) {
		return pad(str, '0', maxLength, false);
	}

	/**
	 * Pads the specified byte array with the MAC_PAD_CHARACTER until multiple of eight bytes.
	 *
	 * @param data the byte array to pad
	 * @return the padded data
	 */
	public static byte[] padByte(byte[] data) {
		int length = data.length;
		if (length % BLOCK_SIZE == 0) {
			return data;
		} else {
			byte[] padData = new byte[((length + BLOCK_SIZE) / BLOCK_SIZE) * BLOCK_SIZE];
			System.arraycopy(data, 0, padData, 0, length);
			for (int i = length; i < padData.length; i++) {
				padData[i] = MAC_PAD_CHARACTER;
			}
			return padData;
		}
	}
	/**
	 * Replaces parameters in string with values passed. If no
	 * values returns original string.
	 * @param pattern the message format pattern
	 * @param values the message format arguments
	 * @return the formatted string
	 */
	public static String insertValuesString(String pattern, Object[] values) {
		return insertValuesString(pattern, values, null);
	}

	/**
	 * Replaces parameters in string with values passed. If no
	 * values returns original string.
	 * @param pattern the message format pattern
	 * @param values the message format arguments
	 * @param timeZoneOffsetKey the timezone to apply to date format substitutions - null for default timezone
	 * @return the formatted string
	 */
	public static String insertValuesString(String pattern, Object[] values, String timeZoneOffsetKey) {
		// Format the message with the parameter values
		String result;
		if (null != values) {
			// single quotes are not allowed in a MessageFormat pattern, so
			// escape all that exist with a second
			MessageFormat messageFormat = new MessageFormat(pattern.replaceAll("'", "''"));

			//QC10234 - replace AM/PM with am/pm
			Format[] formats = messageFormat.getFormats();
			for (Format fmt: formats) {
				if (fmt instanceof SimpleDateFormat) {
					SimpleDateFormat sfd = (SimpleDateFormat)fmt;
					DateFormatSymbols dateSym = sfd.getDateFormatSymbols();
					dateSym.setAmPmStrings(new String[] {"am", "pm"});
					sfd.setDateFormatSymbols(dateSym);

					// apply timezone if specified
					if (timeZoneOffsetKey != null) {
						sfd.setTimeZone(TimeZone.getTimeZone(timeZoneOffsetKey));
					}
				}
			}

			result = messageFormat.format(values);
		} else { // No parameters to resolve
			result = pattern;
		}

		return result;
	}

	/**
	 * This method parses any delimiter separated valued String and
	 * returns a hash set which stores the values obtained from string.
	 *
	 * @param str  - the string that needs to be parsed that has  values separated by delimiter
	 * @param delim - the delimiter
	 * @return the set containing the semicolon separated values
	 */
	public static Set<String> parseString(String str, String delim) {
		Set<String> set = new TreeSet<String>();
		if (str != null && str.length() > 0) {
			String[] strArray = str.split(delim);
			set.addAll(Arrays.asList(strArray));
		}
		return set;
	}

	/**
	 * This method parses any delimiter separated valued Integers and
	 * returns a hash set which stores the values obtained from string.
	 *
	 * @param str  - the string that needs to be parsed that has  values separated by delimiter.
	 * If the string contains any non numerical values, that values will be ignored.
	 * @param delim - the delimiter
	 * @return the set containing the semicolon separated values
	 */
	public static Set<Integer> parseIntegers(String str, String delim) {
		Set<Integer> set = new TreeSet<Integer>();
		if (str != null && str.length() > 0) {
			String[] strArray = str.split(delim);
			for (int i = 0; i < strArray.length; i++) {
				if (isNumber(strArray[i])) {
					set.add(Integer.parseInt(strArray[i]));
				}
			}
		}
		return set;
	}

	/**
	 * This method parses any delimiter separated valued Longs and
	 * returns a hash set which stores the values obtained from string.
	 *
	 * @param str  - the string that needs to be parsed that has  values separated by delimiter.
	 * If the string contains any non numerical values, that values will be ignored.
	 * @param delim - the delimiter
	 * @return the set containing the semicolon separated values
	 */
	public static Set<Long> parseLongs(String str, String delim) {
		Set<Long> set = new TreeSet<Long>();
		if (str != null && str.length() > 0) {
			String[] strArray = str.split(delim);
			for (int i = 0; i < strArray.length; i++) {
				if (isNumber(strArray[i])) {
					set.add(Long.parseLong(strArray[i]));
				}
			}
		}
		return set;
	}

	/**
	 * Method to identify if a string is empty or null
	 * @param subject the string to test
	 * @return the result of the test
	 */
	public static boolean isEmptyOrNull(String subject) {
		return subject == null || EMPTY.equals(subject);
	}

	/**
	 * Method to compare 2 strings for equality. This is null safe and will
	 * return true if both strings are null
	 *
	 * @param source1 source string 1
	 * @param source2 source string 2
	 * @return the result, true if both are null
	 */
	public static boolean equals(String source1, String source2) {
		return source1 == null ? source2 == null : source1.equals(source2);
	}

	/**
	 * Method to compare 2 strings for equality. This is null safe and will
	 * return false if both strings are null or both are empty ""
	 *
	 * @param source1 source string 1
	 * @param source2 source string 2
	 * @return the result, false if both are null or both are empty ""
	 */
	public static boolean equalsNotNullOrEmpty(String source1, String source2) {
		if ((null == source1 && null == source2)
				|| (EMPTY.equals(source1) && EMPTY.equals(source2))) {
			return false;
		}
		return equals(source1, source2);
	}

	/**
	 * Convert a binary string to an array of booleans, where 1 becomes true, and 0 becomes false
	 * @param binaryString the String representation of a binary number, e.g. 0101
	 * @return a boolean array representing the string, e.g. false, true, false, true
	 */
	public static boolean[] toBooleanArray(String binaryString) {
		if (binaryString == null) {
			return null;
		}

		char[] cs = binaryString.toCharArray();

		boolean[] bs = new boolean[cs.length];

		for (int i = 0; i < cs.length; i++) {
			switch (cs[i]) {
				case '0':
					bs[i] = false;
					break;
				case '1':
					bs[i] = true;
					break;
				default:
					throw new IllegalArgumentException(
							"The character " + cs[i] + " is not a valid binary digit");
			}
		}

		return bs;
	}

	/**
	 * Convert an integer string to an array of single digit integers
	 * @param integerString the String representation of a integer number, e.g. "0124"
	 * @return an integer array representing the string, e.g. 0, 1, 2, 4
	 */
	public static int[] toIntegerArray(String integerString) {
		if (integerString == null) {
			return null;
		}

		char[] cs = integerString.toCharArray();

		int[] is = new int[cs.length];

		for (int i = 0; i < cs.length; i++) {
			try {
				is[i] = Integer.parseInt(String.valueOf(cs[i]));
			} catch (Exception e) {
				throw new IllegalArgumentException(
						"The character " + cs[i] + " is not a valid digit");
			}
		}

		return is;
	}

	/**
	 * @param input the string to check
	 * @return true If the input String can be represented by ASCII encoding
	 */
	public static boolean isRepresentableByAscii(final String input) {
		return isRepresentableByWellKnownCharset(input, "ASCII");
	}

	/**
	 * @param input the string to check
	 * @return true If the input String can be represented by ISO-8859-1 encoding
	 */
	public static boolean isRepresentableByLatin1(final String input) {
		return isRepresentableByWellKnownCharset(input, "ISO-8859-1");
	}

	/**
	 * Check if the input string can be represented by UTF8 character set.
	 *
	 * @param input The String to check.
	 * @return true If the input String can be represented, false otherwise.
	 */
	public static boolean isRepresentableByUTF8(final String input) {
		return isRepresentableByWellKnownCharset(input, "UTF-8");
	}

	/**
	 * Use this method if you're confident that the charset exists. You won't then need to handle any
	 * UnsupportedEncodingException in your code. Better yet, add a Strings.isRepresentableByXxxx() method for the
	 * charset you're interested in, which delegates to this one.
	 *
	 * @param input input string
	 * @param charset charset
	 * @return true is input string can be wholly represented by characters from charset
	 */
	public static boolean isRepresentableByWellKnownCharset(final String input, final String charset) {
		try {
			return isRepresentableByCharset(input, charset);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(charset + " not supported as a character encoding.", e);
		}
	}

	/**
	 * Use this method if you're unsure whether the charset exists. You then
	 * have the option of handling the UnsupportedEncodingException in your
	 * code.
	 *
	 * @param input input string
	 * @param charset charset
	 * @return true is input string can be wholly represented by characters from
	 *         charset
	 * @throws java.io.UnsupportedEncodingException if charset is
	 *             unrecognised/unsupported
	 */
	public static boolean isRepresentableByCharset(final String input, final String charset)
			throws UnsupportedEncodingException {
		String encoded = new String(input.getBytes(charset), charset);
		return encoded.equals(input);
	}

	/**
	 * Replace any occurrence that match the regular expression with the given string
	 * replacement
	 * @param input the string in input
	 * @param regex regular expression
	 * @param replacement the string which will replace any regex match
	 * @return the input value with the regex and replacement applied
	 */
	public static String replaceMatch(String input, String regex, String replacement) {
		Pattern pattern = Pattern.compile(regex);
		return replaceMatch(input, pattern, replacement);
	}

	/**
	 * Replace any occurrence that match the regular expression with the given string
	 * replacement
	 * @param input the string in input
	 * @param regex regular expression
	 * @param replacement the string which will replace any regex match
	 * @return the input value with the regex and replacement applied
	 */
	public static String replaceMatch(String input, Pattern regex, String replacement) {
		if (input == null) {
			return null;
		}
		Matcher matcher = regex.matcher(input);
		String result = matcher.replaceAll(replacement);

		return result;
	}

	/**
	 * @param value the value to string
	 * @return the value with the following characters removed <>, %, "
	 */
	public static String stripDisallowedCharacters(String value) {
		return null == value ? null : value.replaceAll(DISALLOWED_CHARACTERS, EMPTY_STRING);
	}

	private static final String DISALLOWED_CHARACTERS = "[<>%\"]";
	private static final String EMPTY_STRING = "";
}
