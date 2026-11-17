package com.nney.tt;

import com.nney.tt.gfx.Disposable;

/**
 * {@link Disposable} fields:
 * <ol>
 * <li>If they are non-null they must be disposed of before they are
 * overwritten.
 * <li>If they are null they must not be disposed of (e.g. during the owners own
 * close() method).
 * </ol>
 * 
 * <p>
 * This litters the code with lots of error-prone boilerplate null-testing.
 * 
 * <p>
 * This class comes the the rescue by encapsulating the field, guaranteeing
 * correct behaviour for any disposable type T.
 */
public final class DisposableField<T extends Disposable> implements Disposable {
	private T item;

	public DisposableField() {
	}

	public DisposableField(T t) {
		item = t;
	}

	@Override
	public void close() {
		if (item != null) {
			item.close();
			item = null;
		}
	}

	public boolean full() {
		return item != null;
	}

	public boolean empty() {
		return !full();
	}

	public T get() {
		return item;
	}

	public void set(T t) {
		close();
		item = t;
	}
}
