package com.nney.json;

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

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class JsonObject extends JsonValue implements Map<String, JsonValue> {
	TreeMap<String, JsonValue> content = new TreeMap<String, JsonValue>();

	public JsonObject(JsonInput input) throws JsonException {
		char c;
		String key;

		if (input.nextClean() != '{') {
			throw input.syntaxError("A JSONObject text must begin with '{'");
		}
		for (;;) {
			c = input.nextClean();
			switch (c) {
			case 0:
				throw input.syntaxError("A JSONObject text must end with '}'");
			case '}':
				return;
			case '"':
				key = input.nextString('"');
				break;
			default:
				input.back();
				key = input.nextTag();
			}

			/*
			 * The key is followed by ':'. We will also tolerate '=' or '=>'.
			 */

			c = input.nextClean();
			if (c == '=') {
				if (input.next() != '>') {
					input.back();
				}
			}
			else if (c != ':') {
				throw input.syntaxError("Expected ':' after key '" + key + "'");
			}
			content.put(key, input.nextValue());

			/*
			 * Pairs are separated by ','. We will also tolerate ';'.
			 */

			switch (input.nextClean()) {
			case ';':
			case ',':
				if (input.nextClean() == '}') {
					return;
				}
				input.back();
				break;
			case '}':
				return;
			default:
				throw input.syntaxError("Expected a ',' or '}'");
			}
		}
	}

	public JsonObject(JsonField... fields) {
		for (JsonField field : fields) {
			content.put(field.name, field.value);
		}
	}

	@Override
	public void writeJson(DataWriter w) throws JsonException {
		w.beginMap();
		for (Map.Entry<String, JsonValue> entry : content.entrySet()) {
			w.writeFieldName(entry.getKey());
			entry.getValue().writeJson(w);
		}
		w.end();
	}

	public @Override
	DataItem requireField(String name) throws DataException {
		DataItem answer = content.get(name);
		if (answer == null) {
			throw new DataException("missing field: " + name);
		}
		return answer;
	}

	@Override
	public boolean fieldExists(String fieldName) {
		return content.containsKey(fieldName);
	}

	//
	// the proxying required to support interface Map ...
	//

	public void clear() {
		content.clear();
	}

	public boolean containsKey(Object key) {
		return content.containsKey(key);
	}

	public boolean containsValue(Object value) {
		return content.containsValue(value);
	}

	public Set<Entry<String, JsonValue>> entrySet() {
		return content.entrySet();
	}

	public JsonValue get(Object key) {
		return content.get(key);
	}

	public boolean isEmpty() {
		return content.isEmpty();
	}

	public Set<String> keySet() {
		return content.keySet();
	}

	public JsonValue put(String key, JsonValue value) {
		return content.put(key, value);
	}

	public void putAll(Map<? extends String, ? extends JsonValue> map) {
		content.putAll(map);
	}

	public JsonValue remove(Object key) {
		return content.remove(key);
	}

	public int size() {
		return content.size();
	}

	@Override
	public String toString() {
		return content.toString();
	}

	public Collection<JsonValue> values() {
		return content.values();
	}

}
