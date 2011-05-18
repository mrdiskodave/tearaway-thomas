package com.nney.tt.geom;

import com.nney.utils.Copyable;
import com.nney.utils.OldCopyable;

public class XRange implements Copyable<XRange>, OldCopyable {
	public int left;
	public int right;

	public XRange(int left, int right) {
		this.left = left;
		this.right = right;
	}

	@Override
	public XRange copy() {
		return new XRange(left, right);
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
		left = x-i;
		right = x+i;
	}
}
