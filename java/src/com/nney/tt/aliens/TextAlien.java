package com.nney.tt.aliens;

import com.nney.tt.AlienMovementServices;

public class TextAlien extends Alien {

	private String text;

	public void setText(String text0) {
		text = text0;
	}
	
	@Override
	public void draw(AlienMovementServices ads) {
		ads.queueDebugText(c, text);
	}

}
