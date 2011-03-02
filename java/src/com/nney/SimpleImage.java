package com.nney;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;

import javax.imageio.ImageIO;

import com.nney.utils.Openable;

public class SimpleImage {
	private int width;
	private int height;
	public int[] pixels;

	SimpleImage(Openable openable) {
		BufferedImage bufferedImage;
		try {
			InputStream is = openable.open();
			bufferedImage = ImageIO.read(is);
			is.close();
		}
		catch (IOException e) {
			throw new RuntimeException(e);
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
}
