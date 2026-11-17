package com.nney.tt.gfx;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Set;
import java.util.TreeSet;

import javax.imageio.ImageIO;

import com.nney.utils.MemoryIoException;

public class SimpleImage {
	final private int width;
	final private int height;

	final private int offset;
	final private int stride;
	final private int[] pixels; // ARGB 32bit words

	public interface SimpleImageProcessor {
		void process(SimpleImage input);
	}

	public interface ChangePixel {
		int change(int c);
	}

	public interface VisitPixel {
		void visit(int c);
	}

	// make sure alpha is 0x00 (transparent) or 0xff (solid)
	// and that if it is transparent there is nothing in the RGB slots
	static ChangePixel IMPORTER = c -> {
		int alpha = c >>> 3 * 8;
		// all
		if (alpha != 0xff) {
			// or nothing
			c = 0;
		}
		return c;
	};

	private SimpleImage(int width, int height, int start, int stride, int[] pixels) {
		this.width = width;
		this.height = height;
		this.offset = start;
		this.stride = stride;
		this.pixels = pixels;
		// this.isView = true;
	}

	private SimpleImage(int width, int height, int[] pixels) {
		this.width = width;
		this.height = height;
		this.pixels = new int[width * height];
		offset = 0;
		stride = width;
		// isView = false;
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
		// isView = false;

		changePixels(IMPORTER);
	}

	public int height() {
		return height;
	}

	public int width() {
		return width;
	}

	private int computeOffset(int x, int y) {
		assert x >= 0 : x;
		assert y >= 0 : y;
		assert x < width : x;
		assert y < height : y;
		return offset + y * stride + x;
	}

	public int get(int x, int y) {
		return this.pixels[computeOffset(x, y)];
	}

	public void put(int x, int y, int c) {
		this.pixels[computeOffset(x, y)] = c;
	}

	public boolean isEntirely(int c) {
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				int p = get(x, y);
				if (p != c) return false;
			}
		}
		return true;
	}

	public Bounds bounds() {
		int left;
		for (left = 0; left < width; left++) {
			if (!view(left, 0, 1, height).isEntirely(0)) break;
		}

		int right;
		for (right = width - 1; right >= 0; right--) {
			if (!view(right, 0, 1, height).isEntirely(0)) break;
		}

		int top;
		for (top = 0; top < height; top++) {
			if (!view(0, top, width, 1).isEntirely(0)) break;
		}

		int bottom;
		for (bottom = height - 1; bottom >= 0; bottom--) {
			if (!view(0, bottom, width, 1).isEntirely(0)) break;
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
				put(x, y, src.get(x, y));
			}
		}
	}

	public void mergeWith(SimpleImage src) {
		assert width == src.width;
		assert height == src.height;
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				int s = src.get(x, y);
				int d = get(x, y);

				int sa = xa(s);
				int da = blend(sa, 0xff, xa(d));
				int dr = blend(sa, xr(s), xr(d));
				int dg = blend(sa, xg(s), xg(d));
				int db = blend(sa, xb(s), xb(d));

				put(x, y, c(da, dr, dg, db));
			}
		}
	}

	static private int blend(int alpha, int src, int dest) {
		return (dest * (0xff - alpha) + src * alpha) / 0xff;
	}

	public void changePixels(ChangePixel p) {
		for (int y = 0; y < height; y++) {
			// System.out.println("Line"+y);
			for (int x = 0; x < width; x++) {
				int o = get(x, y);
				int n = p.change(o);
				// if (o!=n && o!=0xff01ff) {
				// System.out.println(String.format("Changed from %08x to %08x",
				// o, n));
				// }
				put(x, y, n);
			}
		}
	}

	public void visitPixels(VisitPixel p) {
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				int o = get(x, y);
				p.visit(o);
			}
		}
	}

	public Set<Integer> collectPalette() {
		final TreeSet<Integer> pal = new TreeSet<>();
		visitPixels(c -> pal.add(c));
		return pal;
	}

	public void sysout() {
		for (int y = 0; y < height; y++) {
			StringBuilder b = new StringBuilder();
			for (int x = 0; x < width; x++) {
				b.append(get(x, y) < 0 ? "0" : ":");
			}
			System.out.println(b);
		}
	}

	public void fill(int c) {
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				put(x, y, c);
			}
		}
	}

	public void writeP6(OutputStream o) throws IOException {
		String header = String.format("P6\n%s %s\n%s\n", width, height, 255);
		o.write(header.getBytes("ISO-8859-1"));
		byte[] c = new byte[3];
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				int i = get(x, y);
				int a = 0xff - xa(i);
				c[0] = (byte) blend(a, 0xff, xr(i));
				c[1] = (byte) blend(a, 0x00, xg(i));
				c[2] = (byte) blend(a, 0xff, xb(i));
				o.write(c);
			}
		}
	}

	//
	// extract different components
	//

	static private int xb(int i) {
		return i & 0xff;
	}

	static private int xg(int i) {
		return (i >> 8) & 0xff;
	}

	static private int xr(int i) {
		return (i >> 16) & 0xff;
	}

	static private int xa(int i) {
		return (i >> 24) & 0xff;
	}

	//
	// repack components
	//

	private static int c(int da, int dr, int dg, int db) {
		return (da << 24) | (dr << 16) | (dg << 8) | db;
	}
}
