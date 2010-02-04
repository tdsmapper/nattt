PRJ = design

LATEX = pdflatex
# Or if you convert the images:
# LATEX = latex

all: pdf

$(PRJ):
	$(LATEX) $(PRJ) && bibtex $(PRJ) ; $(LATEX) $(PRJ).tex && $(LATEX) $(PRJ).tex

pdf: $(PRJ)
#	dvipdf $(PRJ).dvi

ps: $(PRJ)
	dvips -P cmz -t letter -G0 -o $(PRJ).ps $(PRJ).dvi

spell: 
	(aspell -c -x -t $(PRJ).tex ; for i in `grep -v "^%" $(PRJ).tex |perl -e 'while(<>){chomp;$$s=$$_;if($$s=~m/input{([^}]+)}/){print $$1, "\n"}}'`; do aspell -c -x -t $${i}; done)

count:
	@grep -v "^%" $(PRJ).tex |perl -e 'while(<>){chomp;$$s=$$_;if($$s=~m/input{([^}]+)}/){print $$1, "\n"}}' | xargs cat $(TEX_FILES) | wc

clean:
	rm -f $(PRJ).aux $(PRJ).dvi $(PRJ).log $(PRJ).pdf $(PRJ).ps $(PRJ).bbl $(PRJ).blg
