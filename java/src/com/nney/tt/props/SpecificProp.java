package com.nney.tt.props;

import java.util.List;

public abstract class SpecificProp<T> extends Prop {
	SpecificProp(PropPack pp) {
		super(pp);
	}

	@SuppressWarnings("unchecked")
	public T read() {
		return (T) getFieldAccessor().get();
	}

	public void write(T n) {
		getFieldAccessor().put(n);
	}

	public void writeText(String text) {
	}

	public void addEditButton(List<Button> buttons, final ButtonPressServices bps) {
		buttons.add(new Button() {
			@Override
			public String name() {
				return "edit";
			}

			@Override
			public void press() {
				bps.startEdit(SpecificProp.this, text(), text -> writeText(text));
			}
		});
	}

}
