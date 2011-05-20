package com.nney.tt.geom;

import com.nney.utils.Copyable;

public class XRange implements Copyable<XRange>, Cloneable {
	public int left;
	public int right;

	public XRange(int left, int right) {
		this.left = left;
		this.right = right;
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

	public void around(int x, int i) {
		left = x - i;
		right = x + i;
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
		Box that = (Box) obj;
		return left == that.left && right == that.right;
	}

	@Override
	public String toString() {
		return String.format("XRange(%d, %d)", left, right);
	}
}
