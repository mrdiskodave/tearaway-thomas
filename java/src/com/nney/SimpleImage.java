package com.nney;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.imageio.ImageIO;

import com.nney.utils.MemoryIoException;

public class SimpleImage {
	final private int width;
	final private int height;
	final private int[] pixels; // ARGB 32bit words

	SimpleImage(int width, int height) {
		this.width = width;
		this.height = height;
		this.pixels = new int[width*height];
	}
	
	SimpleImage(byte[] someFileFormatToDecode) {
		BufferedImage bufferedImage;
		try {
			bufferedImage = ImageIO.read(new ByteArrayInputStream(someFileFormatToDecode));
			assert bufferedImage!=null;
		}
		catch (IOException e) {
			throw new MemoryIoException();
		}
		this.width = bufferedImage.getWidth();
		this.height = bufferedImage.getHeight();
		this.pixels = bufferedImage.getRGB(0, 0, width, height, null, 0, width);
	}

	public int getHeight() {
		return height;
	}

	public int getWidth() {
		return width;
	}

	private int computeOffset(int x, int y) {
		assert x<width;
		assert y<height;
		return y*width+x;
	}
	
	public int getPixel(int x, int y) {
		return this.pixels[computeOffset(x, y)];
	}

	public void putPixel(int x, int y, int c) {
		this.pixels[computeOffset(x, y)] = c;
	}
	
	private boolean testLine(int x, int y, int dx, int dy, int l) {
		for (int i=0; i<l; i++) {
			if (isOpaque(x, y)) return true;
			x += dx;
			y += dy;
		}
		return false;
	}

	private boolean testCol(int x) {
		return testLine(x, 0, 0, 1, height);
	}

	private boolean testRow(int y) {
		return testLine(0, y, 1, 0, width);
	}
	

	private boolean isOpaque(int x, int y) {
		// bit of a trick for testing for alpha>=128
		// which works as we only use alpha 0 (transparent) or alpha 255 (opaque)
		int c = getPixel(x, y);
		boolean answer = c<0;
//		System.out.println(String.format("%-4d %-4d %08x %d", x, y, c, answer ? 1 : 0));
		return answer;
	}
	
	public Bounds getBounds() {
		int left;
		for (left=0; left<width; left++) {
			if (testCol(left)) break;
		}
		
		int right;
		for (right=width-1; right>=0; right--) {
			if (testCol(right)) break;
		}

		int top;
		for (top=0; top<height; top++) {
			if (testRow(top)) break;
		}
		
		int bottom;
		for (bottom=height-1; bottom>=0; bottom--) {
			if (testRow(bottom)) break;
		}

		// start-stop not first-last
		right++;
		bottom++;
		
		int width = right-left;
		int height = bottom-top;
		assert width>=0;
		assert height>=0;
		return new Bounds(left, top, width, height);
	}

	public SimpleImage crop(int x, int y, int w, int h) {
		assert x>=0;
		assert y>=0;
		assert w>=0;
		assert h>=0;
		assert x+w <= width;
		assert y+h <= height;
		
		SimpleImage answer = new SimpleImage(w, h);
		for (int iy=0; iy<h; iy++) {
			for (int ix=0; ix<w; ix++) {
				answer.putPixel(ix, iy, getPixel(x+ix, y+iy));
			}
		}
		return answer;
	}

	public SimpleImage crop(Bounds bounds) {
		return crop(bounds.left, bounds.top, bounds.width, bounds.height);
	}
}
