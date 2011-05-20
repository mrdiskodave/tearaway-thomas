package com.nney.tt.mapper;

public class HoverStatus {
	enum STATE {
		PASSIVE,
		HOVER,
		PRESSED
	}
	
	private String hover = "";
	private String pressed = "";

	void move(String name) {
		assert name!=null;
		hover = name;
	}
	
	void down(String name) {
		assert name!=null;
		pressed = name;
	}
	
	boolean up(String name) {
		assert name!=null;
		boolean activation = status(name)==STATE.PRESSED;
		pressed = "";
		return activation;
	}
	
	STATE status(String name) {
		assert name!=null;
		boolean h = name.equals(hover);
		boolean p = name.equals(pressed);
		boolean d = pressed.length()!=0;

		if (h) {
			if (p) {
				return STATE.PRESSED;
			}
			else {
				return d ? STATE.PASSIVE : STATE.HOVER;
			}
		}
		else {
			if (p) {
				return STATE.HOVER;
			}
			else {
				return STATE.PASSIVE;
			}
		}
	}

}
