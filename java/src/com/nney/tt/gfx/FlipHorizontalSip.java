package com.nney.tt.gfx;

import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.SimpleImage.SimpleImageProcessor;

// TODO: unused?
public class FlipHorizontalSip implements SimpleImageProcessor {
	@Override
	public boolean inPlace() {
		return false;
	}

	@Override
	public SimpleImage process(SimpleImage input) {
		final int w = input.width();
		SimpleImage.MovePixel pixelMovement = new SimpleImage.MovePixel() {
			@Override
			public void move(Coord c) {
				c.x = w - 1 - c.x;
			}
		};
		return input.movePixels(pixelMovement);
	}
}
