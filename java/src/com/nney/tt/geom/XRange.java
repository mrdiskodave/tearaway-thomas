package com.nney.tt.geom;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.utils.Copyable;

public class XRange implements Copyable<XRange>, Cloneable {
	public int left;
	public int right;

	public XRange(int left, int right) {
		this.left = left;
		this.right = right;
	}

	public void around(int x, int i) {
		left = x - i;
		right = x + i;
	}

	public void setLeft(int i, int border) {
		left = Math.min(right - border, i);
	}

	public void setRight(int i, int border) {
		right = Math.max(left + border, i);
	}

	public int middle() {
		return (left + right) / 2;
	}

	public void add(int i) {
		left += i;
		right += i;
	}
	
	public void sub(int delta) {
		add(-delta);
	}

	public int width() {
		return right - left + 1;
	}

	@Override
	public XRange copy() {
		return new XRange(left, right);
	}

	@Override
	public Object clone() throws CloneNotSupportedException {
		return super.clone();
	}

	@Override
	public boolean equals(Object obj) {
		XRange that = (XRange) obj;
		return left == that.left && right == that.right;
	}

	@Override
	public String toString() {
		return String.format("XRange(%d, %d)", left, right);
	}
	
	public void resideInside(XRange bigger) {
		int spare = bigger.width() - width();
		assert spare>=0;
		if (!bigger.inside(left) || !bigger.inside(right)) {
			if (left<bigger.left) {
				left = bigger.left;
				right = bigger.right - spare;
			}
			else {
				left = bigger.left + spare;
				right = bigger.right;
			}
		}
	}

	private boolean inside(int x) {
		return x>=left && x<=right;
	}

	public void save(DataDestination d) {
		d.beginArray();
		d.write(left);
		d.write(right);
		d.end();
	}

	public static XRange load(DataItem d) {
		int left = d.requireElement(0).requireInt();
		int right = d.requireElement(1).requireInt();
		return new XRange(left, right);
	}

	
}
