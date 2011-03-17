package com.nney;

public class RealizedFont {
	private final Texture texture;
	private final int kern;
	private final String characters;
	private final Bounds[] boxes;

	public RealizedFont(SimpleImage simpleImage, int kern, Bounds[] boxes, String characters) {
		this.characters = characters;
		this.texture = new Texture(simpleImage);
		this.kern = kern;
		this.boxes = boxes;
	}

	public void draw(int dx, int dy, String text) {
		for (int x = 0; x < text.length(); x++) {
			char c = text.charAt(x);
			int p = characters.indexOf(c);
			if (p >= 0) {
				Bounds z = boxes[p];
				texture.draw(dx, dy, z.left, z.top, z.width, z.height);
				dx += z.width + kern;
			}
		}
	}

}
