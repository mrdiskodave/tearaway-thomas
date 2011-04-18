package com.nney.tt.gfx;

import com.nney.tt.gfx.SimpleImage.SimpleImageProcessor;


public class WhiteOutSip implements SimpleImageProcessor {
	@Override
	public SimpleImage process(SimpleImage input) {
		input.changePixels(new SimpleImage.ChangePixel() {
			@Override
			public int change(int c) {
				int alpha = c >>> 3 * 8;
				if (alpha != 0x00) c = 0xffffffff;
				return c;
			}
		});
		return input;
	}

	@Override
	public boolean inPlace() {
		return true;
	}
}
