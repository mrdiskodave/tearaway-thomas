package com.nney.tt.geom;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.utils.Copyable;
import com.nney.utils.Math2;

public class Coord implements Copyable<Coord>, Cloneable {
	public int x;
	public int y;

	public Coord(int x, int y) {
		this.x = x;
		this.y = y;
	}

	private Coord(Coord c) {
		this(c.x, c.y);
	}

	public Coord() {
		this(0, 0);
	}

	public void sub(Coord other) {
		x -= other.x;
		y -= other.y;
	}

	public void add(Coord other) {
		x += other.x;
		y += other.y;
	}

	public void mul(int z) {
		x *= z;
		y *= z;
	}

	public void div(int z) {
		x /= z;
		y /= z;
	}

	public void and(int x2, int y2) {
		x &= x2;
		y &= y2;
	}

	// short hand, as we do it so much
	public Coord copyAndAdd(int x, int y) {
		Coord answer = copy();
		answer.x += x;
		answer.y += y;
		return answer;
	}

	public Coord copyAndDiv(int z) {
		Coord answer = copy();
		answer.div(z);
		return answer;
	}

	@Override
	public Coord copy() {
		return new Coord(this);
	}

	@Override
	public Object clone() throws CloneNotSupportedException {
		return super.clone();
	}

	@Override
	public boolean equals(Object obj) {
		Coord that = (Coord) obj;
		return that.x == x && that.y == y;
	}

	@Override
	public int hashCode() {
		return x ^ y;
	}

	@Override
	public String toString() {
		return String.format("%sx%s", x, y);
	}
	
	public Coord add2(Coord c) {
		Coord a = copy();
		a.add(c);
		return a;
	}

	public Coord sub2(Coord c) {
		Coord a = copy();
		a.sub(c);
		return a;
	}

	public Coord div2(int z) {
		Coord a = copy();
		a.div(z);
		return a;
	}

	public Coord mul2(int z) {
		Coord a = copy();
		a.mul(z);
		return a;
	}

	public void closer(Coord other, int amount) {
		x = Math2.closer(x, other.x, amount);
		y = Math2.closer(y, other.y, amount);
	}

	public void save(DataDestination d) {
		d.beginArray();
		d.write(x);
		d.write(y);
		d.end();
	}

	public static Coord load(DataItem d) {
		int x = d.requireElement(0).requireInt();
		int y = d.requireElement(1).requireInt();
		return new Coord(x, y);
	}
	


}
