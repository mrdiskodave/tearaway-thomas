package com.nney.tt.props;

import java.util.List;

import com.nney.datanode.DataDestination;
import com.nney.datanode.Node;

public class StringProp extends SpecificProp<String> {
	public StringProp(PropPack pp) {
		super(pp);
	}

	@Override
	public String text() {
		return read();
	}
	
	@Override
	public void writeText(String text) {
		// no parsing required!
		write(text);
	}
	
	@Override
	void save(DataDestination d) {
		d.write(read());
	}

	@Override
	void load(Node d) {
		write(d.requireString());
	}
	
	@Override
	public void getButtons(List<Button> buttons, final ButtonPressServices bps) {
		addEditButton(buttons, bps);
	}
}
