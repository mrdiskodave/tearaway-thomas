package com.nney.tt;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.json.IndentedJsonFormatter;
import com.nney.json.JsonDataDestination;
import com.nney.json.SafeWriter;
import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.AlienWithLocation;
import com.nney.tt.geom.Box;
import com.nney.tt.map.GameMap;
import com.nney.tt.mapper.APS;
import com.nney.tt.resources.TTResource;
import com.nney.utils.Openable;

public class PersistedMap {
	//
	// things from the levelinfo.txt entry
	//
	public int gemsNeeded;
	public int horizon;
	public int timeGiven;
	public int worldNum;
	public int stageNum;
	public String title;

	//
	// things from the dot map
	//
	public GameMap gameMap;
	public Box mapBounds;
	public short playerX;
	public short playerY;
	public boolean playerGoLeft;
	public ArrayList<Alien> aliens = new ArrayList<Alien>();
	public String worldName;
	
	

	public void populateFromLevelInfo(AlienFactory af, int levelNumber) {
		DataItem levelInfo = TTResource.diFromText(TTResource.config("levelinfo.txt"));

		DataItem levels = levelInfo.requireField("levels");
		DataItem level = levels.requireElement(levelNumber);
		gemsNeeded = level.requireField("gemsNeeded").requireInt();
		horizon = level.requireField("horizon").requireInt();
		timeGiven = level.requireField("timeGiven").requireInt();
		worldNum = level.requireField("world").requireInt();
		worldName = levelInfo.requireField("worldNames").requireElement(worldNum-1).requireString();
		stageNum = level.requireField("stage").requireInt();
		title = level.requireField("title").requireString();
		String map = level.requireField("map").requireString();
		loadLegacy(af, TTResource.legacyMap(map));
	}

	private String readChunkId(DataInputStream di) throws IOException {
		StringBuilder sb = new StringBuilder();
		for (int r = 4; r-- > 0;) {
			sb.append((char) di.readByte());
		}
		String id = sb.toString();
		System.out.println("Got chunk: >" + id + "<");
		return id;
	}

	private void loadRawSettings(byte[] rawSettings) throws IOException {
		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(rawSettings));
		playerX = dis.readShort();
		playerY = dis.readShort();
		playerGoLeft = dis.readByte() != 0;

		dis.readByte(); // blkset
		dis.readByte(); // specjsr1
		dis.readByte(); // specjsr2
		dis.readByte(); // specjsr3
		int minx = dis.readByte() & 0xff;
		int maxx = dis.readByte() & 0xff;
		int miny = dis.readByte() & 0xff;
		int maxy = dis.readByte() & 0xff;

		// seemed like we saved an exclusive box
		// where as we need an inclusive one
		maxx++;
		maxy++;

		// also vertical levels were strangely less than 18 wide
		// (when 18 was there actual width)
		maxx = Math.max(minx + (18 - 1), maxx);

		assert maxx <= GameMap.MAP_WIDTH;
		assert maxy <= GameMap.MAP_HEIGHT;
		assert minx < maxx;
		assert miny < maxy;
		mapBounds = new Box(minx, miny, maxx, maxy);
	}

	private void createLegacyAlien(AlienFactory af, int x, int y, int typeCode, byte[] rest) {
		Alien alien = af.make(typeCode);

		if (typeCode == 2 || typeCode == 3) {
			// this is what gem_render -> bob_gem did
			// at rendering time! let's do it early:
			x += 8;
		}

		if (alien instanceof AlienWithLocation) {
			AlienWithLocation awl = (AlienWithLocation) alien;
			awl.c.x = x;
			awl.c.y = y;
		}

		alien.legacyData = rest;
		alien.loadFromLegacyData();
		aliens.add(alien);
	}

	/**
	 * 
	 * @param world
	 *            Only used for {@link World#createAlien(int)}.
	 * @param mapOpenable
	 */
	public void loadLegacy(AlienFactory af, Openable mapOpenable) {
		try {
			InputStream i = mapOpenable.open();
			try {
				DataInputStream di = new DataInputStream(i);
				// get the game map off the front of the stream
				gameMap = new GameMap();
				gameMap.loadFromLegacyMap(di);

				// read the other things
				for (;;) {
					String id = readChunkId(di);
					if (id.equals("set2")) {
						byte[] rawSettings = new byte[0x30];
						di.readFully(rawSettings);
						loadRawSettings(rawSettings);
					}
					else if (id.equals("obj2")) {
						for (;;) {
							int x = di.readShort();
							int y = di.readShort();
							if (x < 0) break;
							int typeCode = di.readByte();
							byte[] rest = new byte[21];
							di.readFully(rest);

							createLegacyAlien(af, x, y, typeCode, rest);
						}
					}
					else if (id.equals("pal2")) {
						while (di.readShort() != -1) {
						}
					}
					else if (id.equals("end!")) {
						break;
					}
					else {
						throw new RuntimeException("Unknown chunk: " + id);
					}
				}
			}
			finally {
				i.close();
			}

		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	void save() {
		SafeWriter sw = new SafeWriter() {
			@Override
			public void write(String text) {
				System.out.print(text);
			}
		};

		IndentedJsonFormatter ijf = new IndentedJsonFormatter(sw);
		ijf.spaciousSeperators();
		DataDestination dd = new JsonDataDestination(ijf);

		dd.beginDict();
		dd.write("objects");
		dd.beginArray();
		for (Alien a : aliens) {
			dd.beginDict();
			dd.write("type");
			dd.write(a.alienInfo.typeCode);
			APS.saveProps(a, dd);
			dd.end();
		}
		dd.end();
		dd.end();
	}

	public String worldName() {
		// TODO Auto-generated method stub
		return null;
	}

	public List<Alien> getAliens() {
		ArrayList<Alien> answer = aliens;
		aliens = null;
		return answer;
		
	}

}
