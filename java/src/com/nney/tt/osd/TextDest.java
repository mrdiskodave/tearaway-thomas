package com.nney.tt.osd;

public interface TextDest {
	void addText(String text);

	void setCol(int v);

	void setKern(int v);

	void addCr();

	void addParagraph();

	void addAdv(int size);

	void addTable(int w, int h);

	void endCell();

	void setHorizontalPadding(int hp);

}