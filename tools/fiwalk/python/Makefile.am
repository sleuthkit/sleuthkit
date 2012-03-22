EXTRA_DIST = demo_plot_times.py demo_readtimes.py demo_sizes.py \
	dfxml.py fiwalk.py histogram.py\
	iblkfind.py icarvingtruth.py idifference.py iextract.py igrep.py \
	imap.py imicrosoft_redact.py iredact-config.txt iredact.py ireport.py\
	dfxml_tool.py iverify.py iverify2.py sanitize_xml.py 

CLEANFILES=g1.xml g2.xml g3.xml g4.xml nps-2009-canon2-gen1.xml

IMAGES=/corp/images/nps/nps-2009-canon2/
GEN6=$(IMAGES)/nps-2009-canon2-gen6.raw

iredact-test:
	python iredact.py config.txt

igt:
	python igroundtruth.py $(IMAGES)/*[1-5].raw $(IMAGES)/*6.raw 

test2:
	python iverify2.py -g foo $(RDIR)/gen4.raw  ~/domex/src/NIST/canon2/gen4.xml 

map:
	python imap.py  $(RDIR)/gen4.raw

test: 
	cp -f small.dmg small.iso
	python iredact.py -r config.txt small.iso
	cmp -b small.dmg small.iso


test3: g1.xml g2.xml g3.xml g4.xml

test4:
	python isectorfind.py $(GEN6) 47520 49217 50690

clean:
	/bin/rm -f $(CLEANFILES) *~ *.bak

nps-2009-canon2-gen1.xml: $(IMAGES)/nps-2009-canon2-gen1.raw
	fiwalk -Xg1.xml -1m $(IMAGES)/nps-2009-canon2-gen1.raw
	fiwalk -Xg2.xml -1m $(IMAGES)/nps-2009-canon2-gen2.raw
	fiwalk -Xg3.xml -1m $(IMAGES)/nps-2009-canon2-gen3.raw
	fiwalk -Xg4.xml -1m $(IMAGES)/nps-2009-canon2-gen4.raw
	fiwalk -Xg5.xml -1m $(IMAGES)/nps-2009-canon2-gen5.raw
	fiwalk -Xg6.xml -1m $(IMAGES)/nps-2009-canon2-gen6.raw

exp:
	python readtimes.py -i /dev/null  -x /corp/images/nps/nps-2009-domexusers/nps-2009-realistic.xml 
