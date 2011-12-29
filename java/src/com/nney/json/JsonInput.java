package com.nney.json;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 Based on code from JSON.org ...

 Copyright (c) 2002 JSON.org

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 The Software shall be used for Good, not Evil.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 */

/**
 * A JsonInput takes a source string and extracts characters and tokens from it.
 */
class JsonInput {
	private final static Pattern HEX4 = Pattern.compile("[0-9a-f]{4}", Pattern.CASE_INSENSITIVE);

	interface JsonBlock {
		void run() throws JsonException;
	}

	private int pos;

	private String text;

	boolean strictCommas = true;

	boolean eof() {
		return pos >= text.length();
	}

	String consumeG(Pattern pattern) {
		Matcher matcher = pattern.matcher(remains());
		if (!matcher.lookingAt()) return null;
		pos += matcher.end();
		return matcher.group();
	}

	boolean consume(String m) {
		boolean answer = remains().startsWith(m);
		if (answer) pos += m.length();
		return answer;
	}

	boolean consume(char c) {
		if (eof()) return false;
		boolean answer = peek() == c;
		if (answer) advance();
		return answer;
	}

	private String remains() {
		String answer = text.substring(pos);
		return answer;
	}

	private int next() {
		int answer = peek();
		advance();
		return answer;
	}

	protected int peek() {
		assert !eof();
		return text.charAt(pos);
	}

	void advance() {
		assert pos < text.length();
		pos++;
	}

	/**
	 * Construct a JSONTokener from a string.
	 * 
	 * @param s
	 *            A source string.
	 */
	JsonInput(String s) {
		text = s;
	}

	void skipWhiteAndComments() {
		while (!eof()) {
			if (consume('#')) {
				while (!(eof() || consume('\r') || consume('\n'))) {
					advance();
				}
			}
			else if (peek() <= ' ') {
				advance();
			}
			else {
				break;
			}
		}
	}

	/**
	 * Return the characters up to the next close quote character. Backslash
	 * processing is done. The formal JSON format does not allow strings in
	 * single quotes, but an implementation is allowed to accept them.
	 * 
	 * @param quote
	 *            The quoting character, either <code>"</code>
	 *            &nbsp;<small>(double quote)</small> or <code>'</code>
	 *            &nbsp;<small>(single quote)</small>.
	 * @return A String.
	 * @throws JsonException
	 *             Unterminated string.
	 */
	String nextString(char quote) throws JsonException {
		StringBuffer sb = new StringBuffer();
		for (;;) {
			if (eof()) {
				throw syntaxError("Unterminated string");
			}
			int c1 = next();
			switch (c1) {
			case '\n':
			case '\r':
			case '\\':
				if (eof()) {
					throw syntaxError("Expected escaped char not EOF");
				}
				int c2 = next();
				switch (c2) {
				case 'b':
					sb.append('\b');
					break;
				case 't':
					sb.append('\t');
					break;
				case 'n':
					sb.append('\n');
					break;
				case 'f':
					sb.append('\f');
					break;
				case 'r':
					sb.append('\r');
					break;
				case 'u':
					sb.append((char) Integer.parseInt(consumeG(HEX4), 16));
					break;
				default:
					sb.append(c2);
				}
				break;
			default:
				if (c1 == quote) {
					return sb.toString();
				}
				sb.append((char) c1);
			}
		}
	}

	void back() {
		pos--;
	}

	/**
	 * Make a JSONException to signal a syntax error.
	 * 
	 * @param message
	 *            The error message.
	 * @return A JSONException object, suitable for throwing
	 */
	JsonException syntaxError(String message) {
		String fullMessage = formatMessage(message);
		return new JsonException(fullMessage);
	}

	private String formatMessage(String message) {
		return message + " at " + TextPosition.fromText(text.substring(0, pos));
	}

	void parseList(char open, char close, String name, JsonBlock contentParser) throws JsonException {
		skipWhiteAndComments();
		if (!consume(open)) {
			throw syntaxError(name + " text must start with '" + open + "'");
		}
		boolean commaExpected = false;
		for (;;) {
			skipWhiteAndComments();
			if (strictCommas) {
				if (consume(close)) return;
				if (commaExpected) {
					boolean gotComma = consume(',');
					if (!gotComma) {
						throw syntaxError("Expected a ',' or '" + close + "'");
					}
					skipWhiteAndComments();
				}
			}
			else {
				boolean gotComma = false;
				if (commaExpected && consume(',')) {
					skipWhiteAndComments();
					gotComma = true;
				}
				if (consume(close)) return;
				if (commaExpected && !gotComma) {
					throw syntaxError("Expected a ',' or '" + close + "'");
				}

			}
			contentParser.run();
			commaExpected = true;
		}
	}
}