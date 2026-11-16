"""Renders the original's three arpeggio sound effects as WAV files.

    python3 arpsfx.py [--amiga-filter] [--original-pitch] [OUTDIR]

FXcollect, FXbgem and FXgem (also called FXfruit) in s195 aren't samples:
each is an 8-byte wave that Paula plays on a loop, with its volume and pitch
changed once a frame by a table (arp_start, arp_cont). This plays those
tables as the original did and writes fxcollect.wav, fxbgem.wav and
fxgem.wav (mono, 8 bit, 44100Hz: what the game takes) to OUTDIR, newdata/fx
by default.

The waves, tables and note periods are read from ../68k/s195.

How the original plays them:

- SFXupdate runs in the vertical blank interrupt (beamsfx=-1): 50 times a
  second, PAL.
- Each table row is: volume (0-64), octave, note (0-11, c to b), pause. The
  row sets the volume and the period, then holds for 1 + pause frames. A
  row starting -1 ends the effect.
- The period is note_table[note] >> octave (sget_period, with d2=2 for the
  8-byte waves), and Paula reads one byte of the wave every period ticks of
  its 3546895Hz clock.

Tuning: note_table's intervals are exact, but it was worked out for the NTSC
clock (3579545Hz), so on the PAL Amiga every note was 15.8 cents flat, and
the >> rounds the high octaves sharp again by up to 14 cents. By default this
retunes them: it uses the NTSC clock, as the game's music player does (where
the same sum gives A = 440Hz), and the exact period note_table[note] / 2^octave.
--original-pitch plays them as the PAL Amiga did instead.

--amiga-filter adds the Amiga's output filters: the fixed one (one pole, about
4.9kHz) and the "LED" filter (two pole Butterworth, about 3.3kHz), which the
game turns on (clr.b $bfe001). Without it the result is unfiltered, like the
game's other sound effects.
"""

import math
import os
import sys
import wave

SOURCE = "../68k/s195"
EFFECTS = ["FXcollect", "FXbgem", "FXgem"]

PAL_CLOCK = 3546895  # what the original ran at
NTSC_CLOCK = 3579545  # what note_table (and the game's music player) is tuned for
FRAMES_PER_SECOND = 50
RATE = 44100
OVERSAMPLE = 32  # sub-samples averaged into each output sample, against aliasing
WAVE_SHIFT = 2  # d2 for sget_period: ln2 of the wave's size in words


def load_source(name):
	with open(name, encoding="latin-1") as f:
		return f.read().splitlines()


def fields(line):
	"""(label, op, operand) of an assembler line; missing parts are ''."""
	code = line.split(";")[0]
	tokens = code.split()
	if not tokens:
		return "", "", ""
	if code[0].isspace():
		tokens = [""] + tokens
	tokens += ["", ""]
	return tokens[0], tokens[1].lower(), tokens[2]


def number(s):
	if s.startswith("$"):
		return int(s[1:], 16)
	if s.startswith("-$"):
		return -int(s[2:], 16)
	return int(s)


def find_label(lines, label):
	for i, line in enumerate(lines):
		if fields(line)[0] == label:
			return i
	raise ValueError("No label " + label + " in " + SOURCE)


def data_after(lines, label, op):
	"""The values of the dc.b or dc.w lines starting at a label."""
	i = find_label(lines, label)
	values = []
	while True:
		lab, o, operand = fields(lines[i])
		if o != op or (lab and lab != label):
			if values:
				return values
		else:
			values += [number(v) for v in operand.split(",")]
		i += 1


def effect_parts(lines, name):
	"""The wave and arp table labels an FX routine loads (lea x,a0)."""
	i = find_label(lines, name)
	labels = []
	for line in lines[i:i + 8]:
		_, op, operand = fields(line)
		if op == "lea":
			labels.append(operand.split(",")[0].split("(")[0])
		if op == "bra":
			break
	wave_label = next(l for l in labels if l.startswith("wave_"))
	arp_label = next(l for l in labels if l.endswith("_arp"))
	return wave_label, arp_label


def arp_rows(values):
	rows = []
	for i in range(0, len(values), 4):
		if values[i] < 0:
			return rows
		rows.append(tuple(values[i:i + 4]))
	raise ValueError("Arp table with no end")


def period(note_table, octave, note, original_pitch):
	shift = octave - 2 + WAVE_SHIFT
	if original_pitch:
		return note_table[note] >> shift
	return note_table[note] / 2 ** shift


def render(wave_bytes, rows, note_table, original_pitch):
	"""The effect as floats from -1 to 1, at RATE."""
	clock = PAL_CLOCK if original_pitch else NTSC_CLOCK
	samples_per_frame = RATE / FRAMES_PER_SECOND
	sub_rate = RATE * OVERSAMPLE
	out = []
	phase = 0.0  # in wave bytes; Paula carries on through the wave between rows
	frame = 0
	for volume, octave, note, pause in rows:
		step = clock / period(note_table, octave, note, original_pitch) / sub_rate
		end = round((frame + 1 + pause) * samples_per_frame)
		while len(out) < end:
			total = 0
			for _ in range(OVERSAMPLE):
				total += wave_bytes[int(phase) % len(wave_bytes)]
				phase += step
			out.append(total / OVERSAMPLE / 128 * volume / 64)
		frame += 1 + pause
	return out


def one_pole(samples, cutoff):
	a = 1 - math.exp(-2 * math.pi * cutoff / RATE)
	y = 0.0
	out = []
	for x in samples:
		y += a * (x - y)
		out.append(y)
	return out


def butterworth2(samples, cutoff):
	k = math.tan(math.pi * cutoff / RATE)
	q = 1 / math.sqrt(2)
	norm = 1 / (1 + k / q + k * k)
	b0 = k * k * norm
	b1 = 2 * b0
	a1 = 2 * (k * k - 1) * norm
	a2 = (1 - k / q + k * k) * norm
	x1 = x2 = y1 = y2 = 0.0
	out = []
	for x in samples:
		y = b0 * x + b1 * x1 + b0 * x2 - a1 * y1 - a2 * y2
		x2, x1, y2, y1 = x1, x, y1, y
		out.append(y)
	return out


def save_wav(name, samples):
	data = bytes(max(0, min(255, round(s * 128) + 128)) for s in samples)
	with wave.open(name, "wb") as w:
		w.setnchannels(1)
		w.setsampwidth(1)
		w.setframerate(RATE)
		w.writeframes(data)


def main(args):
	amiga_filter = "--amiga-filter" in args
	original_pitch = "--original-pitch" in args
	args = [a for a in args if not a.startswith("--")]
	outdir = args[0] if args else "newdata/fx"
	os.makedirs(outdir, exist_ok=True)

	lines = load_source(SOURCE)
	note_table = data_after(lines, "note_table", "dc.w")
	assert len(note_table) == 12, note_table

	for name in EFFECTS:
		wave_label, arp_label = effect_parts(lines, name)
		wave_bytes = data_after(lines, wave_label, "dc.b")
		assert len(wave_bytes) == 8, (wave_label, wave_bytes)
		rows = arp_rows(data_after(lines, arp_label, "dc.b"))

		samples = render(wave_bytes, rows, note_table, original_pitch)
		if amiga_filter:
			samples = butterworth2(one_pole(samples, 4900), 3300)

		file_name = os.path.join(outdir, name.lower() + ".wav")
		save_wav(file_name, samples)
		frames = sum(1 + r[3] for r in rows)
		print("%s: %s, %s, %d rows, %d frames (%.2fs)" % (
			file_name, wave_label, arp_label, len(rows), frames, len(samples) / RATE))


if __name__ == "__main__":
	main(sys.argv[1:])
