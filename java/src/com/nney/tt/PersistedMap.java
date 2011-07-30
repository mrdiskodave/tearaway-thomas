package com.nney.tt;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;

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
	public GameMap gameMap;
	public Box mapBounds;
	public short playerX;
	public short playerY;
	public boolean playerGoLeft;
	public ArrayList<Alien> aliens = new ArrayList<Alien>();

	public int gemsNeeded;
	public int horizon;
	public int timeGiven;
	public String worldName;

	public void populateFromLevelInfo(World world, int lev) {
		DataItem levelInfo = TTResource.diFromText(TTResource.config("levelinfo.txt"));
		levelInfo = levelInfo.requireElement(0);
		gemsNeeded = levelInfo.requireField("gemsNeeded").requireInt();
		horizon = levelInfo.requireField("horizon").requireInt();
		timeGiven = levelInfo.requireField("timeGiven").requireInt();
		String map = levelInfo.requireField("map").requireString();
		worldName = map.substring(0, 1);
		loadLegacy(world, TTResource.legacyMap(map));
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

	private void createLegacyAlien(World world, int x, int y, int type, byte[] rest) {
		Alien alien = world.createAlien2(type);

		if (type == 2 || type == 3) {
			// this is what gem_render -> bob_gem did
			// at rendering time! horrid
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
	public void loadLegacy(World world, Openable mapOpenable) {
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
							int type = di.readByte();
							byte[] rest = new byte[21];
							di.readFully(rest);

							createLegacyAlien(world, x, y, type, rest);
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
	}

}
