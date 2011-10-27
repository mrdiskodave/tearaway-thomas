package com.nney.tt.props;

import com.nney.tt.geom.Coord;

public interface ButtonPressServices {
	Coord getFocus();
	
	void setFocus(Coord c);
	
	void fall(Coord c);
}
