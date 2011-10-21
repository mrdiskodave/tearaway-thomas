package com.nney.tt.aliens;

import org.apache.commons.codec.binary.Hex;

import com.nney.tt.props.PropAnn;

public class LegacyAlien extends AlienWithLocation {
	@PropAnn(name = "Legacy Data", doc = "The data we initialise from", label = "legacyData")
	public String data;
	
	@Override
	public void loadFromLegacyData() {
		data = Hex.encodeHexString(legacyData);
	}
	
	@Override
	public void update() {
		srv.drawDebugText(c, data);
	}
	
	@Override
	public void mapperUpdate() {
		update();
	}
}
