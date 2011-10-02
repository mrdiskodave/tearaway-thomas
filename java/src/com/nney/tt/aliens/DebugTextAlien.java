package com.nney.tt.aliens;

public class DebugTextAlien extends AlienWithLocation {
	private String text;

	public DebugTextAlien(String string) {
		text = string;
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
