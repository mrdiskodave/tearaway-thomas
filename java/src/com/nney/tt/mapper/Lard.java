package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public abstract class Lard {
	public Mapper srv;
	public boolean active;
	
	abstract int key();
	
	void down(Coord c)  {}
	void stroke(Coord c)  {}
	void up(Coord c)  {}
	void always()  {}
	boolean worldCoords() { return true; }
}
