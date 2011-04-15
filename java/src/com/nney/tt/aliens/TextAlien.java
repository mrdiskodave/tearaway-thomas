package com.nney.tt.aliens;

import com.nney.tt.AlienServices;

public class TextAlien extends Alien {

	private String text;

	public void setText(String text0) {
		text = text0;
	}
	
	@Override
	public void update(AlienServices ads) {
		ads.queueDebugText(c, text);
	}

}
