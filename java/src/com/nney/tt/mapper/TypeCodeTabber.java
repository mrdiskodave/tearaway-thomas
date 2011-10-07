package com.nney.tt.mapper;

import java.util.List;

public class TypeCodeTabber<T> {
	private final List<T> list;
	private int pos;

	TypeCodeTabber(List<T> list) {
		this.list = list;
		home();
	}
	
	private TypeCodeTabber(List<T> list2, int pos2) {
		list = list2;
		pos = pos2;
	}

	public T get() {
		return list.get(pos);
	}
	
	public void next() {
		pos++;
		if (pos>=list.size()) {
			home();
		}
	}

	public void home() {
		pos = 0;
	}
	
	public void prev() {
		pos--;
		if (pos<0) {
			end();
		}
	}

	public void end() {
		pos = list.size()-1;
	}
	
	public TypeCodeTabber<T> copy() {
		return new TypeCodeTabber<T>(list, pos);
	}

	public void find(T typeCode) {
		int where = list.indexOf(typeCode);
		if (where>0) pos = where;
	}
}
