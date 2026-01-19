#!/bin/bash

# python3 summarizing_table.py > summarizing_table.tex

BASENAME=main
pdflatex $BASENAME.tex
bibtex $BASENAME
pdflatex $BASENAME.tex
pdflatex $BASENAME.tex
rm $BASENAME.aux $BASENAME.bbl $BASENAME.blg $BASENAME.fdb_latexmk $BASENAME.fls $BASENAME.log $BASENAME.out

gs -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 \
   -dPDFSETTINGS=/prepress \
   -dNOPAUSE -dQUIET -dBATCH \
   -sOutputFile=${BASENAME}-prepress.pdf $BASENAME.pdf

