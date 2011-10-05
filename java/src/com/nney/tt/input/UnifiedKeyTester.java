package com.nney.tt.input;             

public class UnifiedKeyTester extends SubKeys {
	private final HasKeys mouse;
	private final HasKeys keyboard;

	public UnifiedKeyTester(HasKeys mouse, HasKeys keyboard) {
		super(keyboard);
		this.mouse = mouse;
		this.keyboard = keyboard;
	}
	
	@Override
	public boolean isDown(int key) {
		return mouse.isDown(key) || keyboard.isDown(key);
	}

	@Override
	protected int getNext() {
		int k = mouse.justPressed();
		if (k==0) {
			k =keyboard.justPressed(); 
		}
		return k;
	}
}
