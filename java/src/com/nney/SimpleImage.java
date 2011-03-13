package com.nney;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.imageio.ImageIO;

import com.nney.utils.MemoryIoException;

public class SimpleImage {
	final private int width;
	final private int height;
	
	final private int start;
	final private int realWidth;
	
	final private int[] pixels; // ARGB 32bit words
	final private boolean isView;

	public interface MoveTo {
		void move(Coord c);
	}
	
	private SimpleImage(int width, int height, int start, int realWidth, int[] pixels) {
		this.width = width;
		this.height = height;
		this.start = start;
		this.realWidth = realWidth;
		this.pixels = pixels;
		this.isView = true;
	}
	
	private SimpleImage(int width, int height, int[] pixels) {
		this.width = width;
		this.height = height;
		this.pixels = new int[width * height];
		start = 0;
		realWidth = width;
		isView = false;
	}
	
	static public SimpleImage createEmpty(int w, int h) {
		return new SimpleImage(w, h, new int[w*h]);
	}
	
	SimpleImage(byte[] someFileFormatToDecode) {
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
		start = 0;
		realWidth = width;
		isView = false;
	}

	public int getHeight() {
		return height;
	}

	public int getWidth() {
		return width;
	}

	private int computeOffset(int x, int y) {
		assert x < width;
		assert y < height;
		return start + y * realWidth + x;
	}

	public int getPixel(int x, int y) {
		return this.pixels[computeOffset(x, y)];
	}

	public void putPixel(int x, int y, int c) {
		this.pixels[computeOffset(x, y)] = c;
	}
	
	private boolean testLine(int x, int y, int dx, int dy, int counter) {
		int offset = computeOffset(x, y);
		int distance = computeOffset(dx, dy);
		do {
			// <0 is a a trick for testing for alpha>=128 in an int
			// which works as we only use alpha 0 (transparent) or alpha 255
			// (opaque)
			if (this.pixels[offset] < 0)
				return true;
			offset += distance;
		}
		while (--counter != 0);
		return false;
	}

	private boolean testCol(int x) {
		return testLine(x, 0, 0, 1, height);
	}

	private boolean testRow(int y) {
		return testLine(0, y, 1, 0, width);
	}

	public Bounds getBounds() {
		int left;
		for (left = 0; left < width; left++) {
			if (testCol(left))
				break;
		}

		int right;
		for (right = width - 1; right >= 0; right--) {
			if (testCol(right))
				break;
		}

		int top;
		for (top = 0; top < height; top++) {
			if (testRow(top))
				break;
		}

		int bottom;
		for (bottom = height - 1; bottom >= 0; bottom--) {
			if (testRow(bottom))
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


	SimpleImage view(int x, int y, int width, int height) {
		int start = computeOffset(x, y);
		return new SimpleImage(width, height, start, this.width, pixels);
	}


	public SimpleImage view(Bounds bounds) {
		return view(bounds.left, bounds.top, bounds.width, bounds.height);
	}

	public void overwriteWith(SimpleImage src) {
		assert width==src.width;
		assert height==src.height;
		for (int y=0; y<height; y++) {
			for (int x=0; x<width; x++) {
				putPixel(x, y, src.getPixel(x, y));
			}
		}
	}

	public SimpleImage map(MoveTo pixelMovement) {
		SimpleImage answer = SimpleImage.createEmpty(getWidth(), getHeight());
		Coord c = new Coord(); 
		for (int y=0; y<height; y++) {
			for (int x=0; x<width; x++) {
				c.x = x;
				c.y = y;
				pixelMovement.move(c);
				answer.putPixel(c.x, c.y, getPixel(x, y));
			}
		}
		return answer;
	}
}
