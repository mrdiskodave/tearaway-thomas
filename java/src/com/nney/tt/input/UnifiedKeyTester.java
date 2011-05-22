package com.nney.tt.input;             

public class UnifiedKeyTester implements HasKeys {
	private final HasKeys mouse;
	private final HasKeys keyboard;
	private int justPressed;

	public UnifiedKeyTester(HasKeys mouse, HasKeys keyboard) {
		this.mouse = mouse;
		this.keyboard = keyboard;
	}
	
	public void next() {
		justPressed = getNext();
	}

	private int getNext() {
		int x = mouse.justPressed();
		if (x!=0) {
			return x;
		}
		return keyboard.justPressed();
	}

	@Override
	public boolean isDown(int key) {
		return mouse.isDown(key) || keyboard.isDown(key);
	}
	
	@Override
	public int justPressed() {
		return justPressed;
	}

}
