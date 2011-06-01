package com.nney.tt.mapper;

import java.util.List;

public class TypeCodeTabber {
	private final List<Integer> list;
	private int pos;

	TypeCodeTabber(List<Integer> list) {
		this.list = list;
		home();
	}
	
	private TypeCodeTabber(List<Integer> list2, int pos2) {
		list = list2;
		pos = pos2;
	}

	int get() {
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
	
	public TypeCodeTabber copy() {
		return new TypeCodeTabber(list, pos);
	}
}
