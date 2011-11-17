package com.nney.utils;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class HexServices {
	public static byte[] mustDecodeHex(String hexString) {
		int l = hexString.length();
		char content[] = new char[l];
		hexString.getChars(0, l, content, 0);
		try {
			return Hex.decodeHex(content);
		}
		catch (DecoderException e) {
			throw new RuntimeException(e);
		}
	}

}
