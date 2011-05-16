package com.nney.tt.geom;

public class XRange {
	public int left;
	public int right;

	public XRange(int left, int right) {
		this.left = left;
		this.right = right;
	}
	
	public XRange copy() {
		return new XRange(left, right);
	}
}
