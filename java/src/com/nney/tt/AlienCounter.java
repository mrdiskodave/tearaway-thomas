package com.nney.tt;

import com.nney.tt.aliens.Alien;

class AlienCounter implements Visitor<Alien> {
	private final Class<? extends Alien> c;
	private int count;
	
	AlienCounter(Class<? extends Alien> c) {
		this.c = c;
	}

	@Override
	public void visit(Alien a) {
		if (c.isInstance(a)) {
			count++;
		}
	}
	
	int count() {
		return count;
	}
}