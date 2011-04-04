package com.nney;

public class TextAlien extends Alien {

	private String text;

	public void setText(String text0) {
		text = text0;
	}
	
	@Override
	public void draw(AlienDrawingServices ads) {
		ads.debugText(c, text);
	}

}
