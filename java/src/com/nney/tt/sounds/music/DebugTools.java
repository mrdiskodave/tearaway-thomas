package com.nney.tt.sounds.music;

public class DebugTools {
	static String showBin(byte[] b) {
		StringBuffer sb = new StringBuffer();
		for (int x = 0; x < b.length; x++) {
			sb.append(String.format("%02x", b[x]));
		}
		return sb.toString();
	}
}
