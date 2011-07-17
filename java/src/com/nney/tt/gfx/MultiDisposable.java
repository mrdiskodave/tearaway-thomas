package com.nney.tt.gfx;

import java.util.Stack;

public class MultiDisposable implements Disposable {
	private Stack<Disposable> stack = new Stack<Disposable>(); 

	public void add(Disposable d) {
		stack.push(d);
	}

	public void addMany(Disposable... ds) {
		for (Disposable d: ds) {
			add(d);
		}
	}

	@Override
	public void dispose() {
		while (!stack.empty()) {
			stack.pop().dispose();
		}
	}
}
