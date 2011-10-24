package com.nney.tt;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.json.IndentedJsonFormatter;
import com.nney.json.JsonDataDestination;
import com.nney.json.SafeWriter;
import com.nney.json.StringSafeWriter;
import com.nney.tt.aliens.Alien;
import com.nney.tt.map.GameMap;
import com.nney.tt.resources.TTResource;

public class LevelConverter {

	//
	// converts levelinfo.txt to fat levels that include LevelInfo
	// and a levelorder array
	//
	public static void main(String[] args) {
		SafeWriter sw = new StringSafeWriter();
		IndentedJsonFormatter ijf = new IndentedJsonFormatter(sw);
		ijf.spaciousSeperators();
		DataDestination dd = new JsonDataDestination(ijf);
		
		dd.beginArray();
		
		for (int levelNumber = 0; levelNumber<50; levelNumber++) { 
			DataItem levelInfo = TTResource.diFromText(TTResource.config("levelinfo.txt"));

			DataItem levels = levelInfo.requireField("levels");
			DataItem level = levels.requireElement(levelNumber);

			LevelInfo li = new LevelInfo(level);
			
			int worldNum = level.requireField("world").requireInt();
//			li.worldName = levelInfo.requireField("worldNames").requireElement(worldNum - 1).requireString();
			
			String mapName = level.requireField("map").requireString();
			dd.write(mapName);

			System.out.println("LOading "+mapName);

			DataItem mdi = TTResource.diFromText(TTResource.map(mapName));
			DataItem blocks = mdi.requireField("blocks");
			
			WorldInformation wi = WorldInformation.load(li.worldName);
			GameMap gameMap = GameMap.load(blocks);
			gameMap.applyCompress(wi.blockRandomisationTable);
			
			AlienInfoMap alienInfoMap = new AlienInfoMap();
			alienInfoMap.setWorld(li.worldName);
			
			ArrayList<Alien> aliens = new ArrayList<Alien>();
			AlienFactory af = new AlienFactory(alienInfoMap);
			PersistedLevel.staticLoadAliens(aliens, af, mdi.requireField("objects"));
			
			
			String answer = PersistedLevel.staticSave(li, gameMap, aliens);
			try {
				System.out.println("Saving "+mapName);
				FileWriter w = new FileWriter("C:\\Users\\david\\Desktop\\maps\\" + mapName + ".txt");
				w.write(answer);
				w.close();
			}
			catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
		
		dd.end();
		System.out.println(sw.toString());
	}
}
