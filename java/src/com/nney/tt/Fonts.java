package com.nney.tt;

import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.RawFont;
import com.nney.tt.resources.TTResource;
import com.nney.utils.OpenableTools;

public class Fonts implements Disposable {
	public final Font debugFont;
	public final Font font;

	private static String characterRangeHelper(int begin, int end) {
		StringBuilder sb = new StringBuilder();
		for (int x = begin; x < end; x++) {
			sb.append((char) x);
		}
		return sb.toString();
	}

	public Fonts(GraphicsContext gc) {
		debugFont = gc.createFont(new RawFont(2, OpenableTools.mustLoad(TTResource.font("topaz")), 8, 8, false,
				characterRangeHelper(0, 128), '?'));

		font = gc.createFont(new RawFont(1, OpenableTools.mustLoad(TTResource.font("font2")), 16, 11, true,
				"abcdefghijklmnopqrstuvwxyz1234567890.-!?,<>/()' ", '?'));

	}

	@Override
	public void dispose() {
		font.dispose();
		debugFont.dispose();
	}
}
