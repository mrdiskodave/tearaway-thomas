package com.nney.tt.sprites;

import com.nney.tt.gfx.SimpleImage;

public final class LineInfo {

	/**
	 * Generate line info for the given {@link SimpleImage}.
	 * 
	 * @param si
	 * @return The line info.
	 */
	static byte[] generate(SimpleImage si) {
		byte[] li = new byte[si.getHeight() * 2];
		for (int y = 0; y < si.getHeight(); y++) {
			int right = si.getWidth() - 1;
			while (right >= 0 && si.getPixel(right, y) == 0) {
				right--;
			}
			if (right < 0) {
				// empty line
				li[2 * y] = (byte) 0;
				li[2 * y + 1] = (byte) 0;
			}
			else {
				// non-empty line
				int left = 0;
				while (si.getPixel(left, y) == 0) {
					left++;
				}
				int width = right - left + 1;
				li[2 * y] = (byte) left;
				li[2 * y + 1] = (byte) width;
			}
		}
		return li;
	}

	/**
	 * Collide two {@link SimpleImage}s by their line info.
	 * 
	 * @param a
	 *            Line info for image 'a'.
	 * @param b
	 *            Line info for image 'b'.
	 * @param ay
	 *            The row number (i.e. y position) within image 'a' where the
	 *            overlap begins. The overlap begins on the first row of image
	 *            'b'. The overlap cannot begin in the middle of both images (it
	 *            must begin at the top of one or the other) but the caller may
	 *            have to swap their idea of image 'a' and 'b' before starting
	 *            to call this method.
	 * @param axmbx
	 *            The x screen position of image 'a' minus the x screen position
	 *            of image 'b'.
	 * @return Is there a collision? <code>true</code> meaning "there is" or
	 *         <code>false</code> meaning "there is not".
	 */
	public static boolean collide(byte[] a, byte[] b, int ay, int axmbx) {
		ay *= 2;
		int by = 0;
		do {
			int dx = axmbx + a[ay] - b[by];
			if (dx < b[by + 1] && dx > (-a[ay + 1])) return true;
			by += 2;
			ay += 2;
		} while (ay < a.length && by < b.length);
		return false;
	}
}
