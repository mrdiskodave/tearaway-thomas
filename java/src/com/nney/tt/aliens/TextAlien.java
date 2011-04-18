package com.nney.tt.aliens;


public class TextAlien extends Alien {

	private String text;

	public void setText(String text0) {
		text = text0;
	}
	
	@Override
	public void update() {
		srv.queueDebugText(c, text);
	}

}
