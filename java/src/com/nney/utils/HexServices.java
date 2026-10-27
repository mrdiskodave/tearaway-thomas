package com.nney.utils;

public class HexServices {
	private static final char[] DIGITS = "0123456789abcdef".toCharArray();

	public static byte[] mustDecodeHex(String hexString) {
		int l = hexString.length();
		if ((l & 1) != 0) throw new RuntimeException("Odd number of hex digits: " + l);
		byte[] out = new byte[l / 2];
		for (int i = 0; i < out.length; i++) {
			int hi = Character.digit(hexString.charAt(i * 2), 16);
			int lo = Character.digit(hexString.charAt(i * 2 + 1), 16);
			if (hi < 0 || lo < 0) throw new RuntimeException("Not hex at " + (i * 2) + ": " + hexString);
			out[i] = (byte) ((hi << 4) | lo);
		}
		return out;
	}

	public static String encodeHex(byte[] data) {
		char[] out = new char[data.length * 2];
		for (int i = 0; i < data.length; i++) {
			out[i * 2] = DIGITS[(data[i] >> 4) & 0xf];
			out[i * 2 + 1] = DIGITS[data[i] & 0xf];
		}
		return new String(out);
	}
}
