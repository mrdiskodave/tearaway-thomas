package com.nney.tt;

import java.util.ArrayList;

public class CoHub2 {
	final private ArrayList<Coroutine> r = new ArrayList<Coroutine>();
	private int cursor;
	
	synchronized public void add(Coroutine c) {
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
	
	synchronized public Coroutine current() {
		if (cursor>=r.size()) return null;
		
		Coroutine next = r.get(cursor);
		next.notify();
		return next;
	}

}
