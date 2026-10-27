package com.nney.tt;

import java.util.ArrayList;
import java.util.List;

import com.nney.datanode.DataDestination;
import com.nney.datanode.Node;
import com.nney.json.IndentedJsonFormatter;
import com.nney.json.JsonDataDestination;
import com.nney.json.SafeWriter;
import com.nney.json.StringSafeWriter;
import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.LegacyAlien;
import com.nney.tt.map.GameMap;
import com.nney.tt.mapper.APS;
import com.nney.tt.props.OPS;
import com.nney.tt.resources.TTResource;

public class PersistedLevel {
	final private Node levelNode;
	final private String mapName;

	static String getLevelName(int levelNumber) {
		Node levelOrder = TTResource.asNode(TTResource.config("levelorder.txt"));
		return levelOrder.requireElement(levelNumber).requireString();
	}

	public static int levelCount() {
		Node levelOrder = TTResource.asNode(TTResource.config("levelorder.txt"));
		return levelOrder.requireList().length;
	}

	public PersistedLevel(int levelNumber, String overrideLevelText) {
		if (overrideLevelText == null) {
			mapName = getLevelName(levelNumber);
			levelNode = TTResource.asNode(TTResource.map(mapName));
		}
		else {
			mapName = "_internal_test_";
			levelNode = TTResource.asNode(overrideLevelText);
		}
	}

	public String getMapName() {
		return mapName;
	}

	public LevelInfo getLevelInfo() {
		return new LevelInfo(mapName, levelNode.requireField("info"));
	}

	public List<Alien> getAliens(AlienFactory af) {
		List<Alien> aliens = new ArrayList<Alien>();
		staticLoadAliens(aliens, af, levelNode.requireField("objects"));
		return aliens;
	}

	public GameMap getMap() {
		return GameMap.load(levelNode.requireField("blocks"));
	}

	static void staticLoadAliens(List<Alien> aliens, AlienFactory af, Node dis) {
		for (Node di : dis.requireList()) {
			String type = di.requireField("type").requireString();
			Alien alien = af.make(type);
			OPS.loadProps(alien, di);
			if (alien instanceof LegacyAlien) {
				// raw data from the Amiga: if we've since written a class for
				// its type then make one of those from it instead
				alien = af.upgrade((LegacyAlien) alien);
				if (alien == null) continue; // merged into an earlier one
			}
			aliens.add(alien);
		}
	}

	// ---------------------------------------------------------------------------
	// SAVING

	public static String staticSave(LevelInfo li, GameMap gameMap, Iterable<Alien> aliens) {
		SafeWriter sw = new StringSafeWriter();
		IndentedJsonFormatter ijf = new IndentedJsonFormatter(sw);
		ijf.spaciousSeperators();
		DataDestination dd = new JsonDataDestination(ijf);

		dd.beginObject();

		dd.write("info");
		li.save(dd);

		dd.write("objects");
		staticSaveAliens(aliens, dd);
		dd.write("blocks");
		gameMap.save(dd);
		dd.end();

		return sw.toString();
	}

	private static void staticSaveAliens(Iterable<Alien> aliens, DataDestination dd) {
		dd.beginArray();
		ArrayList<Alien> toSave = new ArrayList<Alien>();
		for (Alien a : aliens) {
			if (!a.alienInfo.internal()) {
				toSave.add(a);
			}
		}

		APS.orderAlienList(toSave);

		for (Alien a : toSave) {
			dd.beginObject();
			dd.write("type");
			dd.write(a.alienInfo.name);
			OPS.saveProps(a, dd);
			dd.end();
		}

		dd.end();
	}

	//
	// private String readChunkId(DataInputStream di) throws IOException {
	// StringBuilder sb = new StringBuilder();
	// for (int r = 4; r-- > 0;) {
	// sb.append((char) di.readByte());
	// }
	// String id = sb.toString();
	// // System.out.println("Got chunk: >" + id + "<");
	// return id;
	// }
	//
	// private void loadRawSettings(AlienFactory af, byte[] rawSettings) throws
	// IOException {
	// DataInputStream dis = new DataInputStream(new
	// ByteArrayInputStream(rawSettings));
	// {
	// // read the legacy player position information
	// // as a PlayerAlien
	// int x = dis.readShort();
	// int y = dis.readShort();
	// boolean goLeft = dis.readByte() != 0;
	//
	// // and stuff that into the game the modern way with a
	// // PlayerPositionAlien
	// PlayerAlien alien = new PlayerAlien();
	// af.wrapExisting(alien);
	// alien.c = new Coord(x, y);
	// alien.goLeft = goLeft;
	// aliens.add(alien);
	// }
	//
	// {
	// // read legacy map size
	// // as a MapBoundsAlien
	// dis.readByte(); // blkset
	// dis.readByte(); // specjsr1
	// dis.readByte(); // specjsr2
	// dis.readByte(); // specjsr3
	// int minx = dis.readByte() & 0xff;
	// int maxx = dis.readByte() & 0xff;
	// int miny = dis.readByte() & 0xff;
	// int maxy = dis.readByte() & 0xff;
	//
	// // horizontally, at least, it
	// // seemed like we saved an exclusive box
	// // where as we need an inclusive one
	// // (maybe that was related to have the screen an extra block wide
	// // for
	// // scrolling reasons)
	// maxx++;
	// // maxy++;
	//
	// // also vertical levels were strangely less than 18 wide
	// // (when 18 was there actual width)
	// maxx = Math.max(minx + (18 - 1), maxx);
	//
	// assert maxx < GameMap.MAP_WIDTH;
	// assert maxy < GameMap.MAP_HEIGHT;
	// assert minx < maxx;
	// assert miny < maxy;
	//
	// MapBoundsAlien alien = new MapBoundsAlien();
	// af.wrapExisting(alien);
	// alien.bounds = new Box(minx, miny, maxx, maxy).mult2(Const.BLOCK_SIZE);
	// // System.out.println("Bounds:"+alien.bounds);
	// aliens.add(alien);
	// }
	// }
	//
	//
	//
	//
	// private void createLegacyAlien(AlienFactory af, int x, int y, int
	// typeCode, byte[] rest) {
	//
	// //
	// // adjustments
	// //
	// if (typeCode == 2 || typeCode == 3) {
	// // this is what gem_render -> bob_gem did
	// // at rendering time! let's do it early:
	// x += 8;
	// }
	// // polymorphic bird
	// else if (typeCode == 75) {
	// typeCode = 55;
	// }
	// // polymorphic bear
	// else if (typeCode == 61 || typeCode == 76) {
	// typeCode = 36;
	// }
	//
	// rest[0] = (byte) typeCode;
	//
	// //
	// // creation
	// //
	// Alien alien = af.make(typeCode, x, y, rest);
	// aliens.add(alien);
	// }
	//
	// /**
	// *
	// * @param world
	// * Only used for {@link World#instantiateAttach(int)}.
	// * @param mapOpenable
	// */
	// private void loadLegacy2(AlienFactory af, Openable mapOpenable) {
	// try {
	// InputStream i = mapOpenable.open();
	// try {
	// DataInputStream di = new DataInputStream(i);
	// // get the game map off the front of the stream
	// gameMap = GameMap.loadLegacy(di);
	//
	// // read the other things
	// for (;;) {
	// String id = readChunkId(di);
	// if (id.equals("set2")) {
	// byte[] rawSettings = new byte[0x30];
	// di.readFully(rawSettings);
	// loadRawSettings(af, rawSettings);
	// }
	// else if (id.equals("obj2")) {
	// for (;;) {
	// int x = di.readShort();
	// int y = di.readShort();
	// if (x < 0) break;
	// int typeCode = di.readByte();
	// byte[] rest = new byte[22];
	// di.readFully(rest, 1, 21);
	//
	// createLegacyAlien(af, x, y, typeCode, rest);
	// }
	// }
	// else if (id.equals("pal2")) {
	// while (di.readShort() != -1) {
	// }
	// }
	// else if (id.equals("end!")) {
	// break;
	// }
	// else {
	// throw new RuntimeException("Unknown chunk: " + id);
	// }
	// }
	// }
	// finally {
	// i.close();
	// }
	//
	// }
	// catch (IOException e) {
	// throw new RuntimeException(e);
	// }
	// }

}
