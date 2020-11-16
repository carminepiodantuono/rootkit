#!/bin/bash
# Questo script genera automaticamente un header file in c dalla symbol-table.
# servono 2 argomenti da passare: un file da cui leggere e l'altro dove scrivere

# validazione
if [ $# -ne 2 ]; then
  echo "Usage: `basename $0` {arg}"
  exit 65
fi

# arguments
INPUTFILE=$1
OUTPUTFILE=$2

# creazione dell'header
HEADER="/*This is a C-Headerfile containing all the renamed symbols and adresses of the symbol-table $INPUTFILE*/\n\n#ifndef SYSMAP_H\n#define SYSMAP_H\n\n"

TAIL="\n\n#endif"

# creazione del header e gli si passa la variabile SYMBOLS

echo "Reading and parsing the input file...please be patient.\n"
SYMBOLS=`grep ' [TtDdRr] ' $INPUTFILE | awk '{ gsub(/\./, "_", $3); if (h[$3] != 1) {printf("#define rk_%s 0x%s;\n" ,$3 ,$1)} h[$3] = 1 }'`

# salvataggio il risultato in OUTPUTFILE
echo "Done. Saving results to the specified output file.\n"
echo -e "${HEADER}${SYMBOLS}${TAIL}" > $OUTPUTFILE

echo "Mission accomplished.\n"
exit 0
