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

public class DataObject extends DataItemImpl implements Map<String, DataItem> {
	TreeMap<String, DataItem> content = new TreeMap<String, DataItem>();

	@Override
	public DataItem requireField(String name) throws DataException {
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

	@Override
	public void clear() {
		content.clear();
	}

	@Override
	public boolean containsKey(Object key) {
		return content.containsKey(key);
	}

	@Override
	public boolean containsValue(Object value) {
		return content.containsValue(value);
	}

	@Override
	public Set<Entry<String, DataItem>> entrySet() {
		return content.entrySet();
	}

	@Override
	public DataItem get(Object key) {
		return content.get(key);
	}

	@Override
	public boolean isEmpty() {
		return content.isEmpty();
	}

	@Override
	public Set<String> keySet() {
		return content.keySet();
	}

	@Override
	public DataItem put(String key, DataItem value) {
		return content.put(key, value);
	}

	@Override
	public void putAll(Map<? extends String, ? extends DataItem> map) {
		content.putAll(map);
	}

	@Override
	public DataItem remove(Object key) {
		return content.remove(key);
	}

	@Override
	public int size() {
		return content.size();
	}

	@Override
	public String toString() {
		return content.toString();
	}

	@Override
	public Collection<DataItem> values() {
		return content.values();
	}

	@Override
	public void save(DataDestination d) {
		d.beginDict();
		for (Map.Entry<String, DataItem> entry : content.entrySet()) {
			d.write(entry.getKey());
			entry.getValue().save(d);
		}
		d.end();
	}

}
