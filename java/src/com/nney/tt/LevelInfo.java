package com.nney.tt;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;

public class LevelInfo {
	public final int gemsNeeded;
	public final int timeGiven;
	public final int horizon;
	public final String title;
	public final String worldName;

	public LevelInfo(int gemsNeeded, int timeGiven, int horizon, String title, String worldName) {
		this.gemsNeeded = gemsNeeded;
		this.timeGiven = timeGiven;
		this.horizon = horizon;
		this.title = title;
		this.worldName = worldName;
	}
	
	public LevelInfo(DataItem di) {
		gemsNeeded = di.requireField("gemsNeeded").requireInt();
		horizon = di.requireField("horizon").requireInt();
		timeGiven = di.requireField("timeGiven").requireInt();
		title = di.requireField("title").requireString();
		worldName = di.requireField("worldName").requireString();
	}
	
	void save(DataDestination d) {
		d.beginDict();
		d.write("gemsNeeded");
		d.write(gemsNeeded);
		d.write("timeGiven");
		d.write(timeGiven);
		d.write("horizon");
		d.write(horizon);
		d.write("title");
		d.write(title);
		d.write("world");
		d.write(worldName);
		d.end();
	}
}
