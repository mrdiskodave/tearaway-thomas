package com.nney.tt.mapper;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;

import junit.framework.TestCase;

import com.nney.tt.Const;
import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.gfx.SimpleImage.ChangePixel;
import com.nney.tt.resources.TTResource;
import com.nney.utils.OpenableTools;

public class ToyMaker extends TestCase {

	private static final int SHADOW_BASE = 16;
	private BlockSource src1;
	private BlockSource dest;
	private int destPos;
	private BlockSource src2;

	public void testname() throws Exception {
		TTResource.setResourcePath(new File("C:\\Users\\david\\Desktop\\z"));

		byte[] srcData = OpenableTools.mustLoad(TTResource.blocks("toyparts"));
		SimpleImage canvas = new SimpleImage(srcData);
		src1 = new BlockSource(canvas, Const.BLOCK_SIZE);
		src2 = new BlockSource(canvas.copy(), Const.BLOCK_SIZE);

		// 
		//
		// 0-5 wall with this palette:
		// ff000000
		// ff660000
		// ffaa1100
		// ffdd3300
		//
		// 6-13 backgrounds
		//
		// 14-19 shadows
		//

		for (int shadow = 0; shadow < 6; shadow++) {
			int shadowIdx = SHADOW_BASE + shadow;
			SimpleImage b = getSrc(shadowIdx);
			b.changePixels(new ChangePixel() {
				@Override
				public int change(int c) {
					int alpha = c >>> 3 * 8;
					if (alpha == 0) {
						return 0;
					}
					return 0x80000000;
				}
			});
		}

		SimpleImage destImage = SimpleImage.createEmpty(Const.BLOCK_SIZE * 20, Const.BLOCK_SIZE * 30);
		dest = new BlockSource(destImage, Const.BLOCK_SIZE);

		// colouring and ordering next!! :)
		for (int x = 0; x < 4; x++) {
			copy(x);
		}
		for (int style = 0; style < 5; style++) {
			System.out.println("Style:" + style);
			int stylePos = 6 + style * 2;
			int pips = 4;
			int hidden = 5;
			copy(stylePos, hidden);
			copy(stylePos + 1, hidden);
			copy(stylePos);
			copy(stylePos + 1);
			copy(stylePos, pips);
			copy(stylePos + 1, pips);
			for (int shadow = 0; shadow < 6; shadow++) {
				int shadowIdx = SHADOW_BASE + shadow;
				copy(stylePos, shadowIdx);
				copy(stylePos + 1, shadowIdx);
				copy(stylePos, pips, shadowIdx);
				copy(stylePos + 1, pips, shadowIdx);
			}
		}

		// destImage = SimpleImage.createEmpty(2, 2);
		OutputStream o = new BufferedOutputStream(new FileOutputStream("\\\\10.0.0.3\\x\\x\\tt\\test.pnm"));
		destImage.writeP6(o);
		o.close();
	}
	
	public void styleCopy(int b, int... idxs) {
		
	}
	

	public void copy(int... idxs) {
		SimpleImage d = nextDest();
		for (int idx : idxs) {
			// int idx = idxs[0];
			d.mergeWith(getSrc(idx));
		}
	}

	private SimpleImage getSrc(int i) {
		return src2.getBlock(i);
	}

	private SimpleImage nextDest() {
		return dest.getBlock(destPos++);
	}
}
