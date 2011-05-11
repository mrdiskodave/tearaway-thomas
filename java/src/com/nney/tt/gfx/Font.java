package com.nney.tt.gfx;

public interface Font {

	int draw(int dx, int dy, int fg, int kern, String text);

	int computeWidth(int kern, String text);

	void dispose();

	PrerenderedText preDraw(int fg, int kern, String text);

}