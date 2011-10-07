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

	T get() {
		return list.get(pos);
	}
	
	void next() {
		pos++;
		if (pos>=list.size()) {
			home();
		}
	}

	void home() {
		pos = 0;
	}
	
	void prev() {
		pos--;
		if (pos<0) {
			end();
		}
	}

	void end() {
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
