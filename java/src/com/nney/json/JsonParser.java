package com.nney.json;

import java.util.regex.Pattern;

import com.nney.datanode.DataDestination;
import com.nney.datanode.Node;
import com.nney.datanode.NodeDataDestination;

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
	private void nextValue() throws JsonException {
		skipWhiteAndComments();

		// System.out.println(formatMessage("Looking at "+(char) peek()));

		if (consume('"')) {
			dd.write(nextString('"'));
		}
		else if (consume('{')) {
			back();
			dd.beginObject();
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
					// parse it as a long if we can
					// (certain longs can only be approximated as doubles
					// and there is no need to start getting approximate
					// just yet)
					dd.write(Long.parseLong(n));
				}
				catch (NumberFormatException e1) {
					try {
						// otherwise as a double
						// which is, by its nature, approximate for some values
						dd.write(Double.parseDouble(n));
					}
					catch (NumberFormatException e2) {
						throw syntaxError("Bad number");
					}
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

	public static Node parse(String jsonInputString) throws JsonException {
		NodeDataDestination builder = new NodeDataDestination();
		JsonParser parser = new JsonParser(jsonInputString, builder);
		parser.parse();
		return builder.result();
	}

	public static Node mustParse(String jsonString) {
		try {
			return parse(jsonString);
		}
		catch (JsonException e) {
			throw new RuntimeException(e);
		}
	}
}
