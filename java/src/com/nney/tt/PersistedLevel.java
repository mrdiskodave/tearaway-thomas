package com.nney.tt;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.json.IndentedJsonFormatter;
import com.nney.json.JsonDataDestination;
import com.nney.json.JsonValue;
import com.nney.json.SafeWriter;
import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.MapBoundsAlien;
import com.nney.tt.aliens.PlayerAlien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;
import com.nney.tt.mapper.APS;
import com.nney.tt.resources.TTResource;
import com.nney.utils.Openable;

public class PersistedLevel {
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
	// things from the map file
	//
	public GameMap gameMap;
	public List<Alien> aliens = new ArrayList<Alien>();
	
	// name of the map file
	public String mapName;

	public void populateFromLevelInfo(AlienFactory af, int levelNumber, String configuredMap) {
		DataItem levelInfo = TTResource.diFromText(TTResource.config("levelinfo.txt"));

		DataItem levels = levelInfo.requireField("levels");
		DataItem level = levels.requireElement(levelNumber);
		
		// TODO: these things need to travel in the map file
		gemsNeeded = level.requireField("gemsNeeded").requireInt();
		horizon = level.requireField("horizon").requireInt();
		timeGiven = level.requireField("timeGiven").requireInt();
		title = level.requireField("title").requireString();
		mapName = level.requireField("map").requireString();

		worldNum = level.requireField("world").requireInt();
		stageNum = level.requireField("stage").requireInt();
		
		String worldName = levelInfo.requireField("worldNames").requireElement(worldNum - 1).requireString();
		af.selectWorld(worldName);
		
//		loadLegacy(af, TTResource.legacyMap(mapName));
		
		if (configuredMap==null) {
			loadNew(af, TTResource.diFromText(TTResource.map(mapName)));
		}
		else {
			loadNew(af, JsonValue.mustParse(configuredMap));
		}
	}

	private String readChunkId(DataInputStream di) throws IOException {
		StringBuilder sb = new StringBuilder();
		for (int r = 4; r-- > 0;) {
			sb.append((char) di.readByte());
		}
		String id = sb.toString();
		// System.out.println("Got chunk: >" + id + "<");
		return id;
	}

	private void loadRawSettings(AlienFactory af, byte[] rawSettings) throws IOException {
		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(rawSettings));
		{
			// read the legacy player position information
			// as a PlayerAlien
			int x = dis.readShort();
			int y = dis.readShort();
			boolean goLeft = dis.readByte() != 0;

			// and stuff that into the game the modern way with a
			// PlayerPositionAlien
			PlayerAlien alien = new PlayerAlien();
			af.wrapExisting(alien);
			alien.c = new Coord(x, y);
			alien.goLeft = goLeft;
			aliens.add(alien);
		}

		{
			// read legacy map size
			// as a MapBoundsAlien
			dis.readByte(); // blkset
			dis.readByte(); // specjsr1
			dis.readByte(); // specjsr2
			dis.readByte(); // specjsr3
			int minx = dis.readByte() & 0xff;
			int maxx = dis.readByte() & 0xff;
			int miny = dis.readByte() & 0xff;
			int maxy = dis.readByte() & 0xff;

			// horizontally, at least, it
			// seemed like we saved an exclusive box
			// where as we need an inclusive one
			// (maybe that was related to have the screen an extra block wide
			// for
			// scrolling reasons)
			maxx++;
			// maxy++;

			// also vertical levels were strangely less than 18 wide
			// (when 18 was there actual width)
			maxx = Math.max(minx + (18 - 1), maxx);

			assert maxx < GameMap.MAP_WIDTH;
			assert maxy < GameMap.MAP_HEIGHT;
			assert minx < maxx;
			assert miny < maxy;

			MapBoundsAlien alien = new MapBoundsAlien();
			af.wrapExisting(alien);
			alien.bounds = new Box(minx, miny, maxx, maxy).mult2(Const.BLOCK_SIZE);
			// System.out.println("Bounds:"+alien.bounds);
			aliens.add(alien);
		}
	}

	private void createLegacyAlien(AlienFactory af, int x, int y, int typeCode, byte[] rest) {

		//
		// adjustments
		//
		if (typeCode == 2 || typeCode == 3) {
			// this is what gem_render -> bob_gem did
			// at rendering time! let's do it early:
			x += 8;
		}
		// polymorphic bird
		else if (typeCode == 75) {
			typeCode = 55;
		}
		// polymorphic bear
		else if (typeCode == 61 || typeCode == 76) {
			typeCode = 36;
		}

		rest[0] = (byte) typeCode;

		//
		// creation
		//
		Alien alien = af.make(typeCode, x, y, rest);
		aliens.add(alien);
	}

	/**
	 * 
	 * @param world
	 *            Only used for {@link World#instantiateAttach(int)}.
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
						loadRawSettings(af, rawSettings);
					}
					else if (id.equals("obj2")) {
						for (;;) {
							int x = di.readShort();
							int y = di.readShort();
							if (x < 0) break;
							int typeCode = di.readByte();
							byte[] rest = new byte[22];
							di.readFully(rest, 1, 21);

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
	
	private void loadNew(AlienFactory af, DataItem level) {
		gameMap = new GameMap();
		gameMap.loadMap(level.requireField("blocks"));
		for (DataItem di: level.requireField("objects").requireList()) {
			String type = di.requireField("type").requireString();
			Alien alien = af.make(type);
			APS.loadProps(alien, di);
			aliens.add(alien);
		}
	}

	
	

	void saveNew() {
		String answer = staticSave(gameMap, aliens);
		try {
			String s = mapName;
			s = s.replaceAll(".map", "");
			System.out.println("Saving "+s);
			FileWriter w = new FileWriter("C:\\Users\\david\\Desktop\\maps\\" + s + ".txt");
			w.write(answer);
			w.close();
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static String staticSave(GameMap gameMap, Iterable<Alien> aliens) {
		final StringBuffer sb = new StringBuffer();

		SafeWriter sw = new SafeWriter() {
			@Override
			public void write(String text) {
				sb.append(text);
			}
		};

		IndentedJsonFormatter ijf = new IndentedJsonFormatter(sw);
		ijf.spaciousSeperators();
		DataDestination dd = new JsonDataDestination(ijf);

		dd.beginDict();
		dd.write("objects");
		dd.beginArray();
		
		ArrayList<Alien> toSave = new ArrayList<Alien>();
		
		for (Alien a : aliens) {
			if (!a.alienInfo.internal()) {
				toSave.add(a);
			}
		}

		APS.orderAlienList(toSave);
		
		for (Alien a: toSave) {
			dd.beginDict();
			dd.write("type");
			dd.write(a.alienInfo.name);
			APS.saveProps(a, dd);
			dd.end();
		}

		dd.end();
		dd.write("blocks");
		dd.beginArray();
		gameMap.saveMap(dd);
		dd.end();
		dd.end();

		String answer = sb.toString();
		return answer;
	}

	public List<Alien> getAliens() {
		List<Alien> answer = aliens;
		aliens = null;
		return answer;
	}

	
	



}
