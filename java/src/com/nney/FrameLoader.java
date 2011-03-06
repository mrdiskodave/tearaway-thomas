package com.nney;

import java.io.IOException;

import com.nney.utils.FileOpenable;
import com.nney.utils.Openable;
import com.nney.utils.Pump;

public class FrameLoader {
	byte[] load(Frame f) {
		String filename = "C:\\Users\\david\\Desktop\\newdata\\bobs\\" + f.file + "_"
				+ Integer.toString(f.number) + ".png";
		System.out.println(filename);
		Openable openable = new FileOpenable(filename);
		byte[] data;
		try {
			data = Pump.loadIntoByteArray(openable);
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		return data;
	}
}
