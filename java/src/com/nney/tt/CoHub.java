package com.nney.tt;

import java.util.ArrayList;

public class CoHub {
	final private ArrayList<CoRow> r = new ArrayList<CoRow>();
	private int cursor;
	
	synchronized public void add(CoRow c) {
		r.add(c);
		c.setName(c.name);
		c.start();
	}
	
	synchronized void dispatch() {
		cursor = 0;
	}

	synchronized public void next() {
		cursor++;
	}
	
	synchronized public CoRow current() {
		if (cursor>=r.size()) return null;
		
		CoRow next = r.get(cursor);
		next.notify();
		return next;
	}

}
