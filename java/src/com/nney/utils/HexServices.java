package com.nney.utils;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class HexServices {
	public static byte[] mustDecodeHex(String hexString) {
		char content[] = new char[hexString.length()];
		hexString.getChars(0, hexString.length(), content, 0);
		byte[] data;
		try {
			data = Hex.decodeHex(content);
		}
		catch (DecoderException e) {
			throw new RuntimeException("Bad hex: " + hexString);
		}
		return data;
	}

}
