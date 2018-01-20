for l in $(ls *.txt)
do
	b=$(basename -s .txt ${l})
	../bin/keyword-hunter.py ${l} /tmp/${b}.log ${b}
done
