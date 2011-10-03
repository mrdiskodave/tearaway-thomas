package com.nney.tt.mapper;

import java.util.List;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;

public class BooleanProp extends SpecificProp<Boolean> {
	private final String textTrue;
	private final String textFalse;

	public BooleanProp(PropPack pp) {
		super(pp);
		String t = "YES";
		String f = "NO";
		if (pp.getAnn().xtraDef().equals("leftright")) {
			t = "LEFT";
			f = "RIGHT";
		}
		textTrue = t;
		textFalse = f;
	}

	@Override
	public String text() {
		return read() ? textTrue : textFalse;
	}

	@Override
	void getButtons(List<Button> buttons, ButtonPressServices bps) {
		buttons.add(new Button() {
			@Override
			String name() {
				return "change";
			}

			@Override
			void press() {
				write(!read());
			}
		});
	}

	@Override
	void save(DataDestination d) {
		d.write(read());
	}

	@Override
	void load(DataItem d) {
		write(d.requireBoolean());
	}
}
