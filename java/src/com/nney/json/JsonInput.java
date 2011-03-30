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
 * A JsonInput takes a source string and extracts characters and tokens from
 * it.
 */
class JsonInput {
	private final static Pattern WHITESPACE = Pattern.compile("\\s+");
	private final static Pattern NUMBER = Pattern.compile(
			"-?(0|[1-9][0-9]*)(\\.[0-9]+)?(e[-+][0-9]+)?", Pattern.CASE_INSENSITIVE);
	private final static Pattern CONSTS = Pattern.compile("true|false|null");

	private int pos;

	private String text;

	private boolean more() {
		return pos < text.length();
	}

	Matcher lookingAt(Pattern pattern) {
		Matcher matcher = pattern.matcher(remains());
		if (!matcher.lookingAt()) return null;
		pos = matcher.end();
		return matcher;
	}
	
	boolean lookingAt(String m) {
		boolean answer = remains().startsWith(m);
		if (answer) pos += m.length();
		return answer;
	}
	
	String remains() {
		return text.substring(pos);
	}

	void back() {
		if (pos > 0) {
			pos--;
		}
	}

	char next() {
		if (more()) {
			char c = text.charAt(pos);
			pos++;
			return c;
		}
		return 0;
	}

	public String reportPosition() {
		return " at character " + pos + " of " + text;
	}

    /**
     * Construct a JSONTokener from a string.
     *
     * @param s     A source string.
     */
	JsonInput(String s) {
		text = s;
    }


    /**
     * Get the next n characters.
     *
     * @param n     The number of characters to take.
     * @return      A string of n characters.
     * @throws JsonException
     *   Substring bounds error if there are not
     *   n characters remaining in the source string.
     */
    private String next(int n) throws JsonException {
    	StringBuilder sb = new StringBuilder();
    	while (n--!=0) {
    		char c = next();
            if (c==0) {
            	throw syntaxError("Substring bounds error");
            }
			sb.append(c);
    	}
    	return sb.toString();
     }


    /**
     * Get the next char in the string, skipping whitespace
     * and comments starting with hash.
     * @throws JsonException
     * @return  A character, or 0 if there are no more characters.
     */
    char nextClean() throws JsonException {
        for (;;) {
            char c = next();
            if (c == '#') {
                do {
                    c = next();
                } while (c != '\n' && c != '\r' && c != 0);
            } else if (c == 0 || c > ' ') {
                return c;
            }
        }
    }


    /**
     * Return the characters up to the next close quote character.
     * Backslash processing is done. The formal JSON format does not
     * allow strings in single quotes, but an implementation is allowed to
     * accept them.
     * @param quote The quoting character, either
     *      <code>"</code>&nbsp;<small>(double quote)</small> or
     *      <code>'</code>&nbsp;<small>(single quote)</small>.
     * @return      A String.
     * @throws JsonException Unterminated string.
     */
    public String nextString(char quote) throws JsonException {
        char c;
        StringBuffer sb = new StringBuffer();
        for (;;) {
            c = next();
            switch (c) {
            case 0:
            case '\n':
            case '\r':
                throw syntaxError("Unterminated string");
            case '\\':
                c = next();
                switch (c) {
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
                    sb.append((char)Integer.parseInt(next(4), 16));
                    break;
                case 'x' :
                    sb.append((char) Integer.parseInt(next(2), 16));
                    break;
                default:
                    sb.append(c);
                }
                break;
            default:
                if (c == quote) {
                    return sb.toString();
                }
                sb.append(c);
            }
        }
    }

    /**
     * Get the next value. The value can be a Boolean, Double, Integer,
     * JSONArray, JSONObject, Long, or String, or the JSONObject.NULL object.
     * @throws JsonException If syntax error.
     *
     * @return An object.
     */
    public JsonValue nextValue() throws JsonException {
        char c = nextClean();

        switch (c) {
            case '"':
            case '\'':
                return new JsonString(nextString(c));
            case '{':
            	back();
                return new JsonObject(this);
            case '[':
            	back();
                return new JsonArray(this);
        }

        /*
         * Handle unquoted text. This could be the values true, false, or
         * null, or it can be a number. An implementation (such as this one)
         * is allowed to also accept non-standard forms.
         *
         * Accumulate characters until we reach the end of the text or a
         * formatting character.
         */

        back();
        String s = internalNextString();

        /*
         * If it is true, false, or null, return the proper value.
         */

        if (s.length()==0) {
            throw syntaxError("Missing value.");
        }
        if (s.equalsIgnoreCase("true")) {
            return new JsonBoolean(true);
        }
        if (s.equalsIgnoreCase("false")) {
            return new JsonBoolean(false);
        }
        if (s.equalsIgnoreCase("null")) {
            return new JsonNull();
        }

        // number form
        if (Character.isDigit(s.charAt(0))) {
        	return new JsonNumber(new Double(s));
        }
        
        // bare string form
        //
        // This is beyond what is required in the standard but
        // required by the JsonObject constructor from JsonInput
        // which uses it to parse field names.
        //
        return new JsonString(s);
    }


	private String internalNextString() {
		StringBuffer sb = new StringBuffer();
		for (;;) {
			char firstChar = next();
			if (firstChar < ' ' || ",:]}/\\\"[{;=#".indexOf(firstChar) >= 0) {
				back();
				return sb.toString().trim();
			}
			sb.append(firstChar);
		}
	}
	
	String nextTag() {
		String tag = internalNextString();
		if (tag.length()==0) {
			syntaxError("tag expected");
		}
		return tag;
	}

    /**
     * Make a JSONException to signal a syntax error.
     *
     * @param message The error message.
     * @return  A JSONException object, suitable for throwing
     */
    JsonException syntaxError(String message) {
        return new JsonException(message + reportPosition());
    }

}