package com.nney;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.imageio.ImageIO;

import com.nney.utils.MemoryIoException;

public class SimpleImage {
	private int width;
	private int height;
	private int[] pixels; // ARGB 32bit words

	SimpleImage(byte[] data) {
		BufferedImage bufferedImage;
		try {
			bufferedImage = ImageIO.read(new ByteArrayInputStream(data));
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

	public int getPixel(int x, int y) {
		return this.pixels[y*width+x];
	}
}
