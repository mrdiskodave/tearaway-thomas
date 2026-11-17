package com.nney.tt.flow;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The top ten scores, kept in a small text file in the user's home folder.
 *
 * Starts off with the table from the original game (init_hiscores in s195).
 */
public final class HighScores {
	public static final int SIZE = 10;
	public static final int INITIALS = 3;

	public static final class Entry {
		public final int score;
		public String initials;

		Entry(int score, String initials) {
			this.score = score;
			this.initials = initials;
		}
	}

	private static final Object[][] ORIGINAL = { //
			{ 500000, "deh" }, { 450000, "nic" }, { 400000, "sdb" }, { 350000, "kcv" }, { 300000, "peh" },
			{ 250000, "atw" }, { 200000, "oli" }, { 150000, "jbw" }, { 100000, "jcw" }, { 50000, "wez" } };

	private final List<Entry> entries = new ArrayList<>();
	private final File file;

	/**
	 * @param file
	 *            Where to keep the table, or <code>null</code> to keep it in
	 *            memory only.
	 */
	public HighScores(File file) {
		this.file = file;
		resetToOriginal();
		load();
	}

	public static File defaultFile() {
		return new File(new File(System.getProperty("user.home"), ".tearaway-thomas"), "hiscores.txt");
	}

	private void resetToOriginal() {
		entries.clear();
		for (Object[] o : ORIGINAL) {
			entries.add(new Entry((Integer) o[0], (String) o[1]));
		}
	}

	private void load() {
		if (file == null || !file.isFile()) return;
		try {
			List<Entry> got = new ArrayList<>();
			for (String line : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {
				line = line.trim();
				if (line.isEmpty() || line.startsWith("#")) continue;
				String[] p = line.split("\\s+", 2);
				got.add(new Entry(Integer.parseInt(p[0]), clean(p.length > 1 ? p[1] : "")));
			}
			if (!got.isEmpty()) {
				entries.clear();
				entries.addAll(got);
				sort();
			}
		}
		catch (IOException | RuntimeException e) {
			System.err.println("Couldn't read high scores from " + file + ": " + e);
			resetToOriginal();
		}
	}

	public void save() {
		if (file == null) return;
		StringBuilder sb = new StringBuilder("# Tearaway Thomas high scores\n");
		for (Entry e : entries) {
			sb.append(e.score).append(' ').append(e.initials).append('\n');
		}
		try {
			file.getParentFile().mkdirs();
			Files.write(file.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
		}
		catch (IOException e) {
			System.err.println("Couldn't save high scores to " + file + ": " + e);
		}
	}

	private void sort() {
		// stable, so an equal score goes below the existing ones
		Collections.sort(entries, (a, b) -> Integer.compare(b.score, a.score));
		while (entries.size() > SIZE) {
			entries.remove(entries.size() - 1);
		}
	}

	/** Would this score get into the table? */
	public boolean qualifies(int score) {
		return score > 0 && (entries.size() < SIZE || score > entries.get(entries.size() - 1).score);
	}

	/**
	 * Put a score in the table with blank initials, ready to be filled in.
	 *
	 * @return The new entry, or <code>null</code> if it didn't qualify.
	 */
	public Entry add(int score) {
		if (!qualifies(score)) return null;
		Entry e = new Entry(score, "");
		entries.add(e);
		sort();
		return entries.contains(e) ? e : null;
	}

	public List<Entry> entries() {
		return Collections.unmodifiableList(entries);
	}

	public int rankOf(Entry e) {
		return entries.indexOf(e);
	}

	/** Keep only characters our font can draw. */
	static String clean(String s) {
		StringBuilder sb = new StringBuilder();
		for (char c : s.toLowerCase().toCharArray()) {
			if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || ".-!?".indexOf(c) >= 0) sb.append(c);
			if (sb.length() == INITIALS) break;
		}
		return sb.toString();
	}
}
