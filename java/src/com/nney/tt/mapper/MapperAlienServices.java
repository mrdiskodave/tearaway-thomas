package com.nney.tt.mapper;

import com.nney.tt.AlienServices;
import com.nney.tt.LadderInformation;
import com.nney.tt.Player;
import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

final class MapperAlienServices implements AlienServices {
	private final Mapper mapper;

	MapperAlienServices(Mapper mapper) {
		this.mapper = mapper;
	}

	private void ni() {
		throw new UnsupportedOperationException("service not implemented by map editor");
	}

	@Override
	public void validatePlayerPosition(Coord c) {
		ni();
	}

	@Override
	public void teleportTo(Coord destination) {
		ni();
	}

	@Override
	public boolean showText() {
		ni();
		return false;
	}

	@Override
	public void registerPlayerSpriteForAlienColisions(Coord c, Sprite s) {
		ni();
	}

	@Override
	public int randomness(int n) {
		ni();
		return 0;
	}

	@Override
	public boolean playerFall(Coord where, int fallMax) {
		ni();
		return false;
	}

	@Override
	public void playSoundEffect(String name) {
		ni();
	}

	@Override
	public void oneLessGem(int score, Coord notice) {
		ni();
	}

	@Override
	public void magicDust(Coord where) {
		ni();
	}

	@Override
	public void levelCompleted(Coord exit) {
		ni();
	}

	@Override
	public boolean isOffTheBottom(Coord c) {
		ni();
		return false;
	}

	@Override
	public boolean isExitOpen() {
		ni();
		return false;
	}

	@Override
	public boolean inTheGround(Coord c) {
		ni();
		return false;
	}

	@Override
	public void secretBonusFound() {
	}

	@Override
	public boolean headBounce(Alien alien, Sprite... alienSprites) {
		ni();
		return false;
	}

	@Override
	public Player getThePlayer() {
		ni();
		return null;
	}

	@Override
	public Coord getPlayerPosition() {
		ni();
		return null;
	}

	@Override
	public LadderInformation getLadderInfo() {
		ni();
		return null;
	}

	@Override
	public boolean frameTest(int m) {
		ni();
		return false;
	}

	@Override
	public boolean fall(Coord c, int fallSpeed) {
		ni();
		return false;
	}

	@Override
	public boolean collideBoxWithPlayerHandle(Box box) {
		ni();
		return false;
	}

	@Override
	public boolean collideBoxWithPlayer(Box box) {
		ni();
		return false;
	}

	@Override
	public boolean collideAlienWithPlayerHiRes(Coord alienPos, Sprite alienSprite) {
		ni();
		return false;
	}

	@Override
	public boolean blockInfoIs(Coord c, String name) {
		ni();
		return false;
	}

	@Override
	public String blockInfoHas(Coord c, String prefix) {
		ni();
		return null;
	}

	@Override
	public void awardScore(int score, Coord noticeLocation) {
		ni();
	}

	@Override
	public void awardExtraTime(int seconds) {
		ni();
	}

	@Override
	public void awardExtraLife() {
		ni();
	}

	@Override
	public void applyMapEdits(Coord c, int[][] mapEdits) {
		ni();
	}

	@Override
	public void addAlien(Alien a) {
		ni();
	}

	@Override
	public void addAlien(String name, Coord where) {
		ni();
	}

	@Override
	public boolean keepInMap(Coord c) {
		ni();
		return false;
	}

	@Override
	public boolean inTheGround(int x, int y) {
		ni();
		return false;
	}

	@Override
	public void drawSprite(Coord c, Sprite s, boolean drawWhite) {
		mapper.directDrawSprite(c, s, drawWhite);
	}

	@Override
	public void drawSprite(Coord c, Sprite s) {
		drawSprite(c, s, false);
	}

	@Override
	public void drawDebugText(Coord c, String text) {
		mapper.drawDebugText(c, text);
	}

	@Override
	public int getFrameNumber() {
		return 0;
	}

}