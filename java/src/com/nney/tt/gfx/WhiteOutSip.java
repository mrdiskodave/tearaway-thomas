package com.nney.tt.gfx;

import com.nney.tt.gfx.SimpleImage.SimpleImageProcessor;

/**
 * Make any non-transparent pixel white.
 * 
 * Used to white-out the player to how that he is invulnerable.
 */
public class WhiteOutSip implements SimpleImageProcessor {
	@Override
	public void process(SimpleImage input) {
		input.changePixels(new SimpleImage.ChangePixel() {
			@Override
			public int change(int c) {
				int alpha = c >>> 3 * 8;
				if (alpha != 0x00) c = 0xffffffff;
				return c;
			}
		});
	}
}
