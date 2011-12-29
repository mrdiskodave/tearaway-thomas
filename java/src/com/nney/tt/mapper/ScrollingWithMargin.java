package com.nney.tt.mapper;

import com.nney.utils.Math2;

public class ScrollingWithMargin {
	private final int marginSize;
	private final int screenSize;
	private final int canvasSize;

	private final int[] rev;

	ScrollingWithMargin(int screenSize, int canvasSize, int marginSize) {
		this.screenSize = screenSize;
		this.canvasSize = canvasSize;
		this.marginSize = marginSize;

		rev = new int[canvasSize];

		int p = 0;
		for (int screenPos = 0; screenPos < screenSize; screenPos++) {
			int scrollPos = scrollPosFromScreenPos(screenPos);
			int here = scrollPos + screenPos;
			while (p <= here) {
				rev[p++] = screenPos;
			}
		}
		assert p == canvasSize;
	}

	int scrollPosFromScreenPos(int screenPos) {
		if (screenPos < 0 || screenPos >= screenSize) {
			throw new IllegalArgumentException();
		}

		int protrusion = Math.max(canvasSize - screenSize, 0);
		int spare = screenSize - 1 - marginSize * 2;

		int screenPosWithinScrollZone = Math2.limit(0, spare, screenPos - marginSize);
		return (protrusion * screenPosWithinScrollZone) / spare;
	}

	public int screenPosFromCanvasPos(int canvasPos) {
		return rev[canvasPos];
	}

}
