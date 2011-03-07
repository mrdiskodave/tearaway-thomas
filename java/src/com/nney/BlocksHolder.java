package com.nney;

import java.util.ArrayList;
import java.util.List;

import com.nney.utils.FileOpenable;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class BlocksHolder {
	final int blockSize;
	
	final int gridSize;
	
	List<Texture> textures = new ArrayList<Texture>();

	private int gridCap;
	
	BlocksHolder(int blockSize, int gridSize) {
		this.blockSize = blockSize;
		this.gridSize = gridSize;
		this.gridCap = gridSize*gridSize;
	}
	
	void load() {
		int pos = 0;
		int palEdge = gridSize*blockSize;
		SimpleImage pal = SimpleImage.createEmpty(palEdge, palEdge);
		
		for (int b=0; b<0x199+1; b++) {
			String filename = String.format("C:\\Users\\david\\Desktop\\newdata\\blocks\\w%04x.png", b);
			byte[] someRawGraphicsFile = OpenableTools.load(new FileOpenable(filename));
			SimpleImage block = new SimpleImage(someRawGraphicsFile);
			int x = pos%gridSize;
			int y = pos/gridSize;
			System.out.println(String.format("%03d %03d %03d", pos, x, y));
			x *= blockSize;
			y *= blockSize;
			pal.view(x, y, blockSize, blockSize).overwriteWith(block);
			pos++;
			if (pos==gridCap) {
				ship(pal, pos);
				pos = 0;
			}
		}
		if (pos!=0) {
			ship(pal, pos);
		}

//		abstract Openable findData(Frame f);
//
//		private static Bob bobFromLargeImage(byte[] someRawGraphicsFile) {
//			SimpleImage si = new SimpleImage(someRawGraphicsFile);
//
//			this.texture = new Texture(si);

	}

	private void ship(SimpleImage pal, int pos) {
		System.out.println("ship it "+Integer.toString(pos));
		textures.add(new Texture(pal));
	}
	
	void draw(int block, int dx, int dy) {
		Texture t = textures.get(block / gridCap);
		block %= gridCap;
		int bx = block % gridSize;
		int by = block / gridSize;
		bx *= blockSize;
		by *= blockSize;
		t.draw(dx, dy, bx, by, blockSize, blockSize);
		
		
	}

}
