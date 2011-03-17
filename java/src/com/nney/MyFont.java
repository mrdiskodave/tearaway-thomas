package com.nney;

public class MyFont {
	final private SimpleImage content;
	final private String characters;
	final private Bounds[] boxes;

	public static String characterRangeHelper(int begin, int end) {
		StringBuilder sb = new StringBuilder();
		for (int x = begin; x < end; x++) {
			sb.append((char) x);
		}
		return sb.toString();
	}

	public MyFont(byte[] data, int miniW, int miniH, boolean proportional,
			String characters) {
		this.content = new SimpleImage(data);
		TemporaryBlockSource bs = new TemporaryBlockSource(content, miniW, miniH);
		int count = bs.getBlockCount();
		boxes = new Bounds[count];
		for (int x = 0; x < count; x++) {
			Bounds box = bs.getBlockBounds(x);
			if (proportional) {
				Bounds fittedBox = bs.getBlock(x).getBounds();
				int realWidth = fittedBox.left + fittedBox.width;
				box = new Bounds(box.left, box.top, realWidth, box.height);
				// System.out.println("Char "+x+" "+box);
				// content0.view(box).sysout();
			}
			boxes[x] = box;
		}

		this.characters = characters;
		assert characters.length() == boxes.length : "difference "+characters.length()+" "+boxes.length;
	}

	RealizedFont realize(int fg, int bg, int kern) {
		SimpleImage img = generate(fg, bg);
		// SimpleImage img = content;
		return new RealizedFont(img, kern, boxes, characters);
	}

	public SimpleImage generate(final int fg, final int bg) {
		SimpleImage.ChangePixel c = new SimpleImage.ChangePixel() {
			@Override
			public int change(int c) {
				if (c < 0) {
					return c & fg;
				}
				return bg;
			}
		};
		SimpleImage answer = content.copy();
		answer.transform(c);
		return answer;
	}
}
