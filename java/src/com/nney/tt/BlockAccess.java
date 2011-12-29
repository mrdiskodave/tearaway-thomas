package com.nney.tt;

import com.nney.tt.geom.Coord;

public interface BlockAccess {
	public void set(Coord c, int b);

	public int get(Coord c);

	public int width();

	public int height();
}