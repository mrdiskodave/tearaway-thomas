package com.nney.tt.mapper;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class SuperBatRecord implements BatRecord {
	private final Coord where;
	private final Alien alien;

	public SuperBatRecord(Alien selectedAlien) {
		this.alien = selectedAlien;
		this.where = alien.c.copy();
	}

	@Override
	public boolean inside(Coord c) {
		return Box.around(where, 10).inside(c);
	}

	@Override
	public void press(Coord delta) {
		for (Prop p: APS.propsForAlien(alien)) {
			p.moveBy(delta);
		}
	}
}
