package com.nney.tt.gfx;

public interface Blitable extends Disposable {
	void draw(int dx, int dy);

	/**
	 * Draw it partly see-through.
	 * 
	 * @param opacity
	 *            0 (invisible) to 1 (the same as {@link #draw(int, int)})
	 */
	void drawTranslucent(int dx, int dy, float opacity);
}
