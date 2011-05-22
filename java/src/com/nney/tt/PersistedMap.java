package com.nney.tt;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;

import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.TextAlien;
import com.nney.tt.geom.Box;
import com.nney.tt.map.GameMap;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.AnimsPool;
import com.nney.utils.Openable;

public class PersistedMap {
	public GameMap gameMap;
	public Box mapBounds;
	public short playerX;
	public short playerY;
	public boolean playerGoLeft;
	public ArrayList<Alien> aliens = new ArrayList<Alien>();


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
		minx *= 16;
		maxx *= 16;
		maxx += 15;
		miny *= 16;
		maxy *= 16;
		maxy += 15;
		mapBounds = new Box(minx, miny, maxx, maxy);
	}

	private void loadLegacyAlienIntoWorld(World world, int x, int y, int type,
			byte[] rest) {

		Alien alien = world.createAlien(type);
				
		if (type == 2 || type == 3) {
			// this is what gem_render -> bob_gem does
			x += 8;
		}

		alien.c.x = x;
		alien.c.y = y;
		alien.legacyData = rest;
		alien.loadFromLegacyData();

				// if (alien instanceof LoadsFromSpriteDef) {
				// ((LoadsFromSpriteDef)
				// alien).load(adp.load(alienInfo.animsName));
				// }

		aliens.add(alien);
	}

	/**
	 * 
	 * @param world Only used for {@link World#createAlien(int)}.
	 * @param mapOpenable
	 */
	public void loadLegacy(World world, Openable mapOpenable) {
		try {
			InputStream i = mapOpenable.open();
			DataInputStream di = new DataInputStream(i);
			// get the game map off the front of the stream
			gameMap = new GameMap(di);

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

						loadLegacyAlienIntoWorld(world, x, y, type, rest);
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
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

}
