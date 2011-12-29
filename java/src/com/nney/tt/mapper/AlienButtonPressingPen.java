package com.nney.tt.mapper;

public class AlienButtonPressingPen {
	// @Override
	// void hover(Coord c) {
	// srv.getHoverStatus().move(buttonRecordToString(srv.findButton(c)));
	// }
	//
	// @Override
	// void stroke(Coord c) {
	// hover(c);
	// }
	//
	// @Override
	// boolean down(Coord c) {
	// ButtonRecord br = srv.findButton(c);
	// srv.getHoverStatus().down(buttonRecordToString(br));
	// return br==null;
	// }
	//
	// @Override
	// void up(Coord c) {
	// ButtonRecord selected = srv.findButton(c);
	// if (srv.getHoverStatus().up(buttonRecordToString(selected))) {
	// srv.startAlienEdit();
	// selected.press();
	// srv.endAlienEdit();
	// }
	// }
	//
	// @Override
	// CoordType requiredCoordType() {
	// return CoordType.SCREEN_PIXELS;
	// }
	//
	// private String buttonRecordToString(ButtonRecord br) {
	// if (br==null) return "";
	// return br.getUniqueName();
	// }
}
