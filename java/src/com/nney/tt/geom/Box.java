package com.nney.tt.geom;

import com.nney.datanode.DataDestination;
import com.nney.datanode.Node;
import com.nney.utils.Copyable;

public class Box implements Copyable<Box>, Cloneable {
	public int left;
	public int top;
	public int right;
	public int bottom;

	// inclusive!!

	public Box(int left, int top, int right, int bottom) {
		this.left = left;
		this.top = top;
		this.right = right;
		this.bottom = bottom;
	}

	private Box(Box that) {
		this(that.left, that.top, that.right, that.bottom);
	}

	public static Box fromTopLeftAndSize(int x, int y, int width, int height) {
		return new Box(x, y, x + width - 1, y + height - 1);
	}

	public static Box fromTopLeftAndSize(Coord c, int width, int height) {
		return Box.fromTopLeftAndSize(c.x, c.y, width, height);
	}

	public static Box fromTwoCorners(Coord corner1, Coord corner2) {
		int smallX = Math.min(corner1.x, corner2.x);
		int bigX = Math.max(corner1.x, corner2.x);
		int smallY = Math.min(corner1.y, corner2.y);
		int bigY = Math.max(corner1.y, corner2.y);
		return new Box(smallX, smallY, bigX, bigY);
	}

	public static Box around(Coord c, int l, int t, int r, int b) {
		return new Box(c.x + l, c.y + t, c.x + r, c.y + b);
	}

	public static Box around(Coord c, int width, int height) {
		return around(c, -width, -height, width, height);
	}

	public static Box around(Coord c, int i) {
		return around(c, i, i);
	}

	public static Box around(Coord c) {
		return around(c, 0);
	}

	public boolean constrain(Coord c) {
		boolean changed = false;
		if (c.x < left) {
			c.x = left;
			changed = true;
		}
		if (c.x > right) {
			c.x = right;
			changed = true;
		}
		if (c.y < top) {
			c.y = top;
			changed = true;
		}
		if (c.y > bottom) {
			c.y = bottom;
			changed = true;
		}
		return changed;
	}

	public void accommodate(Coord c) {
		// same as accommodate(Box.around(c))
		left = Math.min(left, c.x);
		right = Math.max(right, c.x);
		top = Math.min(top, c.y);
		bottom = Math.max(bottom, c.y);
	}

	public void accommodate(Box c) {
		left = Math.min(left, c.left);
		right = Math.max(right, c.right);
		top = Math.min(top, c.top);
		bottom = Math.max(bottom, c.bottom);
	}

	public boolean inside(Coord c) {
		return insideX(c.x) && insideY(c.y);
	}

	public boolean insideY(int y) {
		return y >= top && y <= bottom;
	}

	public boolean insideX(int x) {
		return x >= left && x <= right;
	}

	public void shrink(int i) {
		left += i;
		right -= i;
		top += i;
		bottom -= i;
	}

	public int width() {
		return 1 + right - left;
	}

	public int height() {
		return 1 + bottom - top;
	}

	public void add(Coord c) {
		left += c.x;
		right += c.x;
		top += c.y;
		bottom += c.y;
	}

	public void sub(Coord c) {
		left -= c.x;
		right -= c.x;
		top -= c.y;
		bottom -= c.y;
	}

	public Box add2(Coord c) {
		Box a = copy();
		a.add(c);
		return a;
	}

	public Box sub2(Coord c) {
		Box a = copy();
		a.sub(c);
		return a;
	}

	public Box mult2(int z) {
		Box a = copy();
		a.mult(z);
		return a;
	}

	public Coord topLeft() {
		return new Coord(left, top);
	}

	public Coord topRight() {
		return new Coord(right, top);
	}

	public Coord bottomLeft() {
		return new Coord(left, bottom);
	}

	public Coord bottomRight() {
		return new Coord(right, bottom);
	}

	public Coord middle() {
		return new Coord((left + right) / 2, (top + bottom) / 2);
	}

	public void setLeft(int i, int border) {
		left = Math.min(right - border, i);
	}

	public void setTop(int i, int border) {
		top = Math.min(bottom - border, i);
	}

	public void setRight(int i, int border) {
		right = Math.max(left + border, i);
	}

	public void setBottom(int i, int border) {
		bottom = Math.max(top + border, i);
	}

	@Override
	public Box copy() {
		return new Box(this);
	}

	@Override
	public Object clone() throws CloneNotSupportedException {
		return super.clone();
	}

	@Override
	public boolean equals(Object obj) {
		Box that = (Box) obj;
		return left == that.left && right == that.right && top == that.top && bottom == that.bottom;
	}

	@Override
	public String toString() {
		return String.format("Box(%d, %d, %d, %d)", left, top, right, bottom);
	}

	public int xEnd() {
		return right + 1;
	}

	public int yEnd() {
		return bottom + 1;
	}

	private void validate() {
		if (right < left) {
			int t = right;
			right = left;
			left = t;
		}
		if (bottom < top) {
			int t = bottom;
			bottom = top;
			top = t;
		}
	}

	public void resideInside(Box container) {
		int spareX = Math.max(0, container.width() - width());
		if (!container.insideX(left) || !container.insideX(right) || spareX == 0) {
			if (left < container.left) {
				left = container.left;
				right = container.right - spareX;
			}
			else {
				left = container.left + spareX;
				right = container.right;
			}
		}

		int spareY = Math.max(0, container.height() - height());
		if (!container.insideY(top) || !container.insideY(bottom) || spareY == 0) {
			if (top < container.top) {
				top = container.top;
				bottom = container.bottom - spareY;
			}
			else {
				top = container.top + spareY;
				bottom = container.bottom;
			}
		}
	}

	public XRange toXRange() {
		return new XRange(left, right);
	}

	public void mult(int z) {
		left *= z;
		right *= z;
		right += z - 1;

		top *= z;
		bottom *= z;
		bottom += z - 1;
	}

	public void save(DataDestination d) {
		d.beginArray();
		d.write(left);
		d.write(top);
		d.write(right);
		d.write(bottom);
		d.end();
	}

	public static Box load(Node d) {
		int left = d.requireElement(0).requireInt();
		int top = d.requireElement(1).requireInt();
		int right = d.requireElement(2).requireInt();
		int bottom = d.requireElement(3).requireInt();
		return new Box(left, top, right, bottom);
	}

	/**
	 * Snap to some grid. We snap outwards: only ever getting bigger, never
	 * smaller.
	 * 
	 * @param gridSize
	 *            Grid size which must be a power of two.
	 */
	public void snapOutTo(int gridSize) {
		left &= -gridSize;
		top &= -gridSize;

		right &= -gridSize;
		right += gridSize - 1;
		bottom &= -gridSize;
		bottom += gridSize - 1;
	}

	public long area() {
		long a = width();
		a *= height();
		return a;
	}

	public Coord centre() {
		int x = left + right;
		int y = top + bottom;
		assert x % 2 == 0;
		assert y % 2 == 0;
		return new Coord(x / 2, y / 2);
	}

	public Box resideInside2(Box bigger) {
		Box c = copy();
		c.resideInside(bigger);
		return c;
	}

}
