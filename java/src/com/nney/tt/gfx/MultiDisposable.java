package com.nney.tt.gfx;

import java.util.Stack;

public class MultiDisposable implements Disposable {
	private Stack<Disposable> stack = new Stack<Disposable>();

	public MultiDisposable() {
	}

	public MultiDisposable(Disposable... ds) {
		for (Disposable d : ds) {
			add(d);
		}
	}

	public void add(Disposable d) {
		stack.push(d);
	}

	public void addMany(Disposable... ds) {
		for (Disposable d : ds) {
			add(d);
		}
	}

	@Override
	public void dispose() {
		while (!stack.empty()) {
			stack.pop().dispose();
		}
	}

	public static <T extends Disposable> T add(MultiDisposable md, T t) {
		md.add(t);
		return t;
	}
}
