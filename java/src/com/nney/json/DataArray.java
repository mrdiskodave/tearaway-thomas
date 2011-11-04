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
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Vector;

public class DataArray extends DataItemImpl implements List<DataItem> {
	Vector<DataItem> content = new Vector<DataItem>();
	
	// ---------------------------------------------------------------------------
	// Support for DataItem

	@Override
	public void save(DataDestination d) {
		d.beginArray();
		for (DataItem v : content) {
			v.save(d);
		}
		d.end();
	}

	@Override
	public DataItem requireElement(int position) throws DataException {
		if (position >= content.size() || position < 0) {
			throw new DataException("position " + position + " not found in array of length " + content.size());
		}
		return content.get(position);
	}

	@Override
	public DataItem[] requireList() throws DataException {
		return content.toArray(new DataItem[content.size()]);
	}


	// ---------------------------------------------------------------------------
	// Delegates for interface List

	@Override
	public void add(int index, DataItem element) {
		content.add(index, element);
	}

	@Override
	public boolean add(DataItem o) {
		return content.add(o);
	}

	@Override
	public boolean addAll(Collection<? extends DataItem> c) {
		return content.addAll(c);
	}

	@Override
	public boolean addAll(int index, Collection<? extends DataItem> c) {
		return content.addAll(index, c);
	}

	@Override
	public void clear() {
		content.clear();
	}

	@Override
	public boolean contains(Object elem) {
		return content.contains(elem);
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		return content.containsAll(c);
	}

	@Override
	public DataItem get(int index) {
		return content.get(index);
	}

	@Override
	public int indexOf(Object elem) {
		return content.indexOf(elem);
	}

	@Override
	public boolean isEmpty() {
		return content.isEmpty();
	}

	@Override
	public Iterator<DataItem> iterator() {
		return content.iterator();
	}

	@Override
	public int lastIndexOf(Object elem) {
		return content.lastIndexOf(elem);
	}

	@Override
	public ListIterator<DataItem> listIterator() {
		return content.listIterator();
	}

	@Override
	public ListIterator<DataItem> listIterator(int index) {
		return content.listIterator(index);
	}

	@Override
	public DataItem remove(int index) {
		return content.remove(index);
	}

	@Override
	public boolean remove(Object o) {
		return content.remove(o);
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		return content.removeAll(c);
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		return content.retainAll(c);
	}

	@Override
	public DataItem set(int index, DataItem element) {
		return content.set(index, element);
	}

	@Override
	public int size() {
		return content.size();
	}

	@Override
	public List<DataItem> subList(int fromIndex, int toIndex) {
		return content.subList(fromIndex, toIndex);
	}

	@Override
	public Object[] toArray() {
		return content.toArray();
	}

	@Override
	public <T> T[] toArray(T[] a) {
		return content.toArray(a);
	}

	@Override
	public String toString() {
		return content.toString();
	}

}
