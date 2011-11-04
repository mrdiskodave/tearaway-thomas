package com.nney.json;

import java.util.regex.Pattern;

public class JsonParser extends JsonInput {
	protected final static Pattern NUMBER = Pattern.compile("-?(0|[1-9][0-9]*)(\\.[0-9]+)?(e[-+][0-9]+)?",
			Pattern.CASE_INSENSITIVE);

	private final DataDestination dd;

	JsonParser(String s, DataDestination dd) {
		super(s);
		this.dd = dd;
	}

	/**
	 * Get the next value. The value can be a Boolean, Double, Integer,
	 * JSONArray, JSONObject, Long, or String, or the JSONObject.NULL object.
	 * 
	 * @throws JsonException
	 *             If syntax error.
	 * 
	 * @return An object.
	 */
	public void nextValue() throws JsonException {
		skipWhiteAndComments();

		// System.out.println(formatMessage("Looking at "+(char) peek()));

		if (consume('"')) {
			dd.write(nextString('"'));
		}
		else if (consume('{')) {
			back();
			dd.beginDict();
			JsonBlock block = new JsonBlock() {
				@Override
				public void run() throws JsonException {
					if (!consume('"')) {
						throw syntaxError("Expected key string");
					}
					String key = nextString('"');
					skipWhiteAndComments();
					if (!consume(':')) {
						throw syntaxError("Expected ':' after key '" + key + "'");
					}
					dd.write(key);
					nextValue();
				}
			};
			parseList('{', '}', "Object", block);
			dd.end();
		}
		else if (consume('[')) {
			back();
			dd.beginArray();
			JsonBlock block = new JsonBlock() {
				@Override
				public void run() throws JsonException {
					nextValue();
				}
			};
			parseList('[', ']', "Array", block);
			dd.end();
		}
		else if (consume("true")) {
			dd.write(true);
		}
		else if (consume("false")) {
			dd.write(false);
		}
		else if (consume("null")) {
			dd.writeNull();
		}
		else {
			String n = consumeG(NUMBER);
			if (n != null) {
				try {
					dd.write(Double.parseDouble(n));
				}
				catch (NumberFormatException e) {
					throw syntaxError("Bad number");
				}
			}
			else {
				throw syntaxError("Not a JSON item: " + (char) peek());
			}
		}
	}

	public void parse() throws JsonException {
		nextValue();
		skipWhiteAndComments();
		if (!eof()) {
			throw syntaxError("Expected end of file");
		}
	}
}
