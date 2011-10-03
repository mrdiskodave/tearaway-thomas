package com.nney.tt.mapper;

import java.util.List;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;

public class IntegerProp extends SpecificProp<Integer> {
	public IntegerProp(PropPack pp) {
		super(pp);
	}

	@Override
	public String text() {
		return Integer.toString(read());
	}
	
	@Override
	void getButtons(List<Button> buttons, ButtonPressServices bps) {
		buttons.add(new Button() {
			@Override
			String name() {
				return "more";
			}

			@Override
			void press() {
				write(read()+1);
			}
		});
		buttons.add(new Button() {
			@Override
			String name() {
				return "less";
			}

			@Override
			void press() {
				write(read()-1);
			}
		});
	}
	
	@Override
	void save(DataDestination d) {
		d.write(read());
	}

	@Override
	void load(DataItem d) {
		write(d.requireInt());
	}
}
