package com.nney.tt.mapper;

public class HoverStatus {
	private String hover = "";
	private String pressed = "";

	void move(String name) {
		assert name!=null;
		hover = name;
	}
	
	void down(String name) {
		System.out.println("DOWN:"+name);
		assert name!=null;
		pressed = name;
	}
	
	boolean up(String name) {
		System.out.println("UP:"+name);
		assert name!=null;
		boolean activation = status(name)==ButtonState.PRESSED;
		pressed = "";
		return activation && name.length()>0;
	}

	ButtonState status(String name) {
		ButtonState answer = status0(name);
//		System.out.println("Status "+name+" is "+answer);
		return answer;
	}

	ButtonState status0(String name) {
		assert name!=null;
		boolean isHoveringOverUs = name.equals(hover);
		boolean isPressedOnUs = name.equals(pressed);

		if (isHoveringOverUs) {
			if (isPressedOnUs) {
				return ButtonState.PRESSED;
			}
			else {
				boolean isPressedOnSomethingElse = pressed.length()>0;
				if (isPressedOnSomethingElse) {
					return ButtonState.PASSIVE;
				}
				else {
					return ButtonState.HOVER;
				}
			}
		}
		else {
			if (isPressedOnUs) {
				return ButtonState.HOVER;
			}
			else {
				return ButtonState.PASSIVE;
			}
		}
	}
}
