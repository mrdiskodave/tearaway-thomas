package com.nney.tt;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.tt.props.PropAnn;

public class LevelInfo {
	@PropAnn(doc = "How many gems must be collected before the exit opens?")
	public int gemsNeeded;

	@PropAnn(doc = "How many seconds is the player allowed to complete the level?")
	public int timeGiven;
	
	@PropAnn(doc = "What horizon sits behind the level?")
	public int horizon;
	
	@PropAnn(doc = "What is the title of this level?")
	public String title;
	
	@PropAnn(doc = "What is the filename of this level?")
	public String filename;

	public String worldName;


	public LevelInfo(int gemsNeeded, int timeGiven, int horizon, String title, String worldName) {
		this.gemsNeeded = gemsNeeded;
		this.timeGiven = timeGiven;
		this.horizon = horizon;
		this.title = title;
		this.worldName = worldName;
	}
	
	public LevelInfo(String mapName0, DataItem di) {
		gemsNeeded = di.requireField("gemsNeeded").requireInt();
		horizon = di.requireField("horizon").requireInt();
		timeGiven = di.requireField("timeGiven").requireInt();
		title = di.requireField("title").requireString();
		worldName = di.requireField("world").requireString();
		filename = mapName0;
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
