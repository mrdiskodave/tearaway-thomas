package com.nney.tt.aliens;

public class DebugTextAlien extends AlienWithLocation {
	private String text;

	public void setText(String text0) {
		text = text0;
	}

	@Override
	public void update() {
		srv.drawDebugText(c, text);
	}

	@Override
	public void mapperUpdate() {
		update();
	}
}
