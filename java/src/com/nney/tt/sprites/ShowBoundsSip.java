package com.nney.tt.sprites;

import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.gfx.SimpleImage.SimpleImageProcessor;

public class ShowBoundsSip implements SimpleImageProcessor {
	@Override
	public SimpleImage process(SimpleImage input) {
		input.changePixels(new SimpleImage.ChangePixel() {
			@Override
			public int change(int c) {
				int alpha = c >>> 3 * 8;
				if (alpha != 0xff) c = 0xff00ffff;
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
