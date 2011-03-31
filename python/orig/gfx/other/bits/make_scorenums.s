chars=37

	lea	pra,a0
	lea	vb,a5
	bsr	IFFscan
	lea	buffer,a1
	moveq	#40,d0
	bsr	IFFgetpicture

	lea	buffer,a0
	lea	b,a1

	moveq	#chars-1,d7
next_char
	move.l	a0,-(a7)
	moveq	#22-1,d6
next_line
	move.b	(a0),(a1)+
	lea	40(a0),a0
	dbf	d6,next_line

	move.l	(a7)+,a0
	addq.l	#1,a0
	dbf	d7,next_char
done	
	rts

IFFscan:
	; a0=addr of file to scan
	; file must always be scanned before anything else
	cmp.l	#"FORM",(a0)+
	bne.s	IFFerror
	move.l	(a0)+,d0
	cmp.l	#"ILBM",(a0)+
	bne.s	IFFerror
	subq.l	#4,d0			Size=Size-ILBM
	move.l	d0,IFFsize-vb(a5)
	move.l	a0,IFFnextchunk-vb(a5)

IFFml:
	tst.l	IFFsize-vb(a5)
	beq.s	IFFdone
	move.l	IFFnextchunk-vb(a5),a0
	move.l	(a0)+,d0		chunk name
	move.l	(a0)+,d1		chuck length
	movem.l	d1/a0,-(sp)
	; d1=IFFchunklen
	; a0=IFFchunkpos
	btst	#0,d1
	beq.s	IFFnwa
	addq	#1,d1
IFFnwa:	add.l	d1,a0
	addq	#8,d1
	sub.l	d1,IFFsize-vb(a5)
	move.l	a0,IFFnextchunk-vb(a5)
	movem.l	(sp)+,d1/a0
	; big switch command
	; on jump A0=chunk start adr
	cmp.l	#"BMHD",d0
	bne.s	IFFninfo
	move.l	a0,IFFinfo-vb(a5)
IFFninfo:
	cmp.l	#"BODY",d0
	bne.s	IFFnbody
	move.l	a0,IFFbody
IFFnbody:
	cmp.l	#"CMAP",d0
	bne.s	IFFncmap
	move.l	a0,IFFcmap
	divu	#3,d1			chunk length div 3 =#colours
	move.w	d1,IFFcolcount-vb(a5)
IFFncmap:
	bra.s	IFFml
IFFerror:
	nop
IFFdone:
	rts





IFFmakecopper:
	; a1=dest for copper code that sets the pallete
	move.w	#$0180,d1
	moveq	#2,d2
	bra.s	IFFgct

IFFgetcolours:
	; a1=dest for pallete (could be memory or dff180)
	clr.l	d2
IFFgct:	move.w	IFFcolcount-vb(a5),d7
	move.l	IFFcmap-vb(a5),a0
	subq.w	#1,d7
IFFgcl:	move.b	(a0)+,d0	R
	lsl.w	#4,d0
	or.b	(a0)+,d0	G
	lsl.w	#4,d0
	or.b	(a0)+,d0	B
	lsr.w	#4,d0
	move.w	d1,(a1)		store copper command
	add.l	d2,a1		if d2=0 then it will be wiped over
	addq.w	#2,d1
	move.w	d0,(a1)+	store it
	dbf	d7,IFFgcl
	rts

IFFgetpicture:
	; a1=dest
	; d0=xp
	move.l	IFFbody-vb(a5),a0
	move.l	IFFinfo-vb(a5),a3
	move.w	(a3),d1
	lsr.w	#3,d1		=pic width in bytes
	sub.w	d1,d0		=modulus
	move.w	2(a3),d2	=pic hieght
	subq.w	#1,d2
	clr.w	d3
	move.b	8(a3),d3
	subq.w	#1,d3
Ignl:	move.w	d3,d4
Ignp:	bsr.s	IFFunpack
	lea	0(a1,d0.w),a1
	dbf	d4,Ignp
	dbf	d2,Ignl
	rts


IFFunpack:
	; unpacks an iff line
	; a0=source
	; a1=dest
	; a3=info chunk pointer
	; d1=line width in bytes
	movem.l	d0-d7,-(sp)
	move.w	d1,d0
notdone:move.w	d0,d7
	tst.b	10(a3)			compression on?
	beq.s	copydata
	move.b	(a0)+,d1
	bpl.s	nopack
	neg.b	d1
	ext.w	d1
	move.b	(a0)+,d2
	sub.w	d1,d0
	subq.w	#1,d0
ploop:	move.b	d2,(a1)+
	dbf	d1,ploop
	bra.s	donecheck
nopack:	addq.b	#1,d1
	move.b	d1,d7
copydata:
	sub.w	d7,d0
	subq.w	#1,d7			DBF form
cdl:	move.b	(a0)+,(a1)+
	dbf	d7,cdl
donecheck:
	tst.w	d0
	bne.s	notdone
	movem.l	(sp)+,d0-d7
	rts

**** END IFF STUFF ****

vb:
IFFnextchunk:	dc.l	0
IFFsize:	dc.l	0
; pointers found by chunk scanner.....
IFFinfo:	dc.l	0		Width,Depth,Crunch and # Planes
IFFbody:	dc.l	0		Main Data (may be crunched)
IFFcmap:	dc.l	0		Colour Map Structure
; and
IFFcolcount:	dc.w	0		# colours


pra:	incbin	"hw_sprites.lbm"
buffer	ds.b	40*2*256
b:	ds.b	chars*2*11
e:
