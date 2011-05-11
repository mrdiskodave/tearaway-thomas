package com.nney.tt;

import java.io.IOException;

import com.nney.json.DataItem;
import com.nney.json.JsonException;
import com.nney.json.JsonValue;
import com.nney.tt.map.BlockAliasTable;
import com.nney.tt.map.BlockInformation;
import com.nney.tt.resources.TTResource;
import com.nney.utils.StringIO;

public class WorldInformation {
	public final BlockAliasTable blockRandomisationTable;
	public final BlockAliasTable invisibleBlockHiding;
	public final BlockInformation blockInformation;
	public final LadderInformation ladderInformation;

	private WorldInformation(BlockAliasTable rt, BlockAliasTable ih, BlockInformation bi, LadderInformation li) {
		this.blockRandomisationTable = rt;
		this.invisibleBlockHiding = ih;
		this.blockInformation = bi;
		this.ladderInformation = li;
	}

	static public WorldInformation load(String worldName) {
		try {
			String t = StringIO.loadText(TTResource.blockDef(worldName), null);
			JsonValue v = JsonValue.parse(t);
			BlockInformation bi = new BlockInformation(v.requireField("spec"));
			LadderInformation ladderInfo = null;
			if (v.fieldExists("ladder")) {
				DataItem ladderDi = v.requireField("ladder");
				int top = ladderDi.requireField("top").requireInt();
				int bottom = ladderDi.requireField("bottom").requireInt();
				ladderInfo = new LadderInformation(top, bottom);
			}
			BlockAliasTable rt = new BlockAliasTable(v.requireField("rt"));
			BlockAliasTable ih = new BlockAliasTable(v.requireField("invisibleBlockHiding"));
			return new WorldInformation(rt, ih, bi, ladderInfo);
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		catch (JsonException e) {
			throw new RuntimeException(e);
		}
	}
}
