package com.nney.tt.gfx;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.TreeSet;

import javax.imageio.ImageIO;

import com.nney.tt.geom.Coord;
import com.nney.utils.MemoryIoException;

public class SimpleImage {
	final private int width;
	final private int height;

	final private int offset;
	final private int stride;
	final private int[] pixels; // ARGB 32bit words

	final private boolean isView;

	public interface MovePixel {
		void move(Coord c);
	}

	public interface ChangePixel {
		int change(int c);
	}

	public interface TestPixel {
		boolean test(int c);
	}

	public interface VisitPixel {
		void visit(int c);
	}

	// make sure alpha is 0x00 (transparent) or 0xff (solid)
	// and that if it is transparent there is nothing in the RGB slots
	static ChangePixel IMPORTER = new ChangePixel() {
		@Override
		public int change(int c) {
			int alpha = c >>> 3 * 8;
			if (alpha != 0xff)
				c = 0; // pure transparent (nothing in the RBG slots)
			return c;
		}
	};

	private SimpleImage(int width, int height, int start, int stride, int[] pixels) {
		this.width = width;
		this.height = height;
		this.offset = start;
		this.stride = stride;
		this.pixels = pixels;
		this.isView = true;
	}

	private SimpleImage(int width, int height, int[] pixels) {
		this.width = width;
		this.height = height;
		this.pixels = new int[width * height];
		offset = 0;
		stride = width;
		isView = false;
	}

	static public SimpleImage createEmpty(int w, int h) {
		return new SimpleImage(w, h, new int[w * h]);
	}

	public SimpleImage copy() {
		SimpleImage dest = createEmpty(width, height);
		dest.overwriteWith(this);
		return dest;
	}

	public SimpleImage(byte[] someFileFormatToDecode) {
		BufferedImage bufferedImage;
		try {
			bufferedImage = ImageIO.read(new ByteArrayInputStream(someFileFormatToDecode));
			assert bufferedImage != null;
		}
		catch (IOException e) {
			throw new MemoryIoException();
		}
		this.width = bufferedImage.getWidth();
		this.height = bufferedImage.getHeight();
		this.pixels = bufferedImage.getRGB(0, 0, width, height, null, 0, width);
		offset = 0;
		stride = width;
		isView = false;

		changePixels(IMPORTER);
	}

	public int getHeight() {
		return height;
	}

	public int getWidth() {
		return width;
	}

	private int computeOffset(int x, int y) {
		assert x >= 0: x;
		assert y >= 0: y;
		assert x < width: x;
		assert y < height: y;
		return offset + y * stride + x;
	}

	public int getPixel(int x, int y) {
		return this.pixels[computeOffset(x, y)];
	}

	public void putPixel(int x, int y, int c) {
		this.pixels[computeOffset(x, y)] = c;
	}

	public boolean isEntirely(int c) {
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				int p = getPixel(x, y);
				if (p != c)
					return false;
			}
		}
		return true;
	}

	public Bounds getBounds() {
		int left;
		for (left = 0; left < width; left++) {
			if (!view(left, 0, 1, height).isEntirely(0))
				break;
		}

		int right;
		for (right = width - 1; right >= 0; right--) {
			if (!view(right, 0, 1, height).isEntirely(0))
				break;
		}

		int top;
		for (top = 0; top < height; top++) {
			if (!view(0, top, width, 1).isEntirely(0))
				break;
		}

		int bottom;
		for (bottom = height - 1; bottom >= 0; bottom--) {
			if (!view(0, bottom, width, 1).isEntirely(0))
				break;
		}

		// start-stop not first-last
		right++;
		bottom++;

		int width = right - left;
		int height = bottom - top;
		assert width > 0;
		assert height > 0;
		return new Bounds(left, top, width, height);
	}

	public SimpleImage view(int x, int y, int width, int height) {
		assert x >= 0;
		assert y >= 0;
		assert width >= 0;
		assert height >= 0;
		assert x + width <= this.width;
		assert y + height <= this.height;

		int start = computeOffset(x, y);
		return new SimpleImage(width, height, start, stride, pixels);
	}

	public SimpleImage view(Bounds bounds) {
		return view(bounds.left, bounds.top, bounds.width, bounds.height);
	}

	public void overwriteWith(SimpleImage src) {
		assert width == src.width;
		assert height == src.height;
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				putPixel(x, y, src.getPixel(x, y));
			}
		}
	}

	public SimpleImage movePixels(MovePixel pixelMovement) {
		SimpleImage answer = SimpleImage.createEmpty(getWidth(), getHeight());
		Coord c = new Coord();
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				c.x = x;
				c.y = y;
				pixelMovement.move(c);
				answer.putPixel(c.x, c.y, getPixel(x, y));
			}
		}
		return answer;
	}

	public void changePixels(ChangePixel p) {
		for (int y = 0; y < height; y++) {
			// System.out.println("Line"+y);
			for (int x = 0; x < width; x++) {
				int o = getPixel(x, y);
				int n = p.change(o);
				// if (o!=n && o!=0xff01ff) {
				// System.out.println(String.format("Changed from %08x to %08x",
				// o, n));
				// }
				putPixel(x, y, n);
			}
		}
	}

	public void visitPixels(VisitPixel p) {
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				int o = getPixel(x, y);
				p.visit(o);
			}
		}
	}
	
	public int[] collectPalette() {
		final TreeSet<Integer> pal = new TreeSet<Integer>();
		visitPixels(new VisitPixel() {
			@Override
			public void visit(int c) {
				pal.add(c);
			}
		});
		Integer[] boxed = (Integer[]) pal.toArray(new Integer[pal.size()]);
		int[] unboxed = new int[boxed.length];
		for (int x=0; x<boxed.length; x++) {
			unboxed[x] = boxed[x];
		}
		return unboxed;
	}

	public void sysout() {
		for (int y = 0; y < height; y++) {
			StringBuilder b = new StringBuilder();
			for (int x = 0; x < width; x++) {
				b.append(getPixel(x, y) < 0 ? "0" : ":");
			}
			System.out.println(b);
		}
	}

	public void fill(int c) {
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				putPixel(x, y, c);
			}
		}
	}
}
