package com.nney.tt.gfx;

public class RawFont {
	public final int scaleDown;
	public final byte[] data;
	public final int miniW;
	public final int miniH;
	public final boolean proportional;
	public final String characters;
	public final char missingChar;

	public RawFont(int scaleDown, byte[] data, int miniW, int miniH, boolean proportional, String characters, char missingChar) {
		this.scaleDown = scaleDown;
		this.data = data;
		this.miniW = miniW;
		this.miniH = miniH;
		this.proportional = proportional;
		this.characters = characters;
		this.missingChar = missingChar;
	}
}
