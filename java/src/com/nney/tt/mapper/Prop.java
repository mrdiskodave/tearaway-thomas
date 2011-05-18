package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Coord;

public abstract class Prop {
	protected final AlienProp aprop;
	protected final FieldAccessor fa;

	public Prop(AlienProp aprop, FieldAccessor fa) {
		this.aprop = aprop;
		this.fa = fa;
	}

	abstract void createBats(Coord alien, BatTarget rt);

	abstract void moveTo(int what, Coord where);

	public String name() {
		return aprop.name();
	}

	public String doc() {
		return aprop.doc();
	}

	abstract public String text();

}
