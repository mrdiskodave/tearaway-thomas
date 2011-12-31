package com.nney.tt.mapper;

import com.nney.utils.Math2;

public class ScrollingWithMargin {
	private final int marginSize;
	private final int screenSize;
	private final int canvasSize;

	private final int protrusion;

	private int[] rev;
	private int spare;

	ScrollingWithMargin(int screenSize, int canvasSize, int marginSize) {
		// System.out.println(String.format(">>> screenSize%d canvasSize%d",
		// screenSize, canvasSize));
		this.screenSize = screenSize;
		this.canvasSize = canvasSize;
		this.marginSize = marginSize;

		protrusion = Math.max(canvasSize - screenSize, 0);

		if (protrusion != 0) {
			spare = screenSize - marginSize * 2;
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
	}

	int scrollPosFromScreenPos(int screenPos) {
		if (protrusion == 0) return 0;
		if (screenPos < 0 || screenPos >= screenSize) {
			throw new IllegalArgumentException();
		}

		int screenPosWithinScrollZone = Math2.limit(0, spare, screenPos - marginSize);
		int answer = (protrusion * screenPosWithinScrollZone) / spare;
		assert answer <= protrusion;
		// System.out.println(String.format("p%d a%d", protrusion, answer));
		return answer;
	}

	public int screenPosFromCanvasPos(int canvasPos) {
		if (protrusion == 0) return 0;
		return rev[canvasPos];
	}

}
