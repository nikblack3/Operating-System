#!/bin/bash

TRACEDIR=./traceprogs
CURDIR=`pwd`
COUNTER=${TRACEDIR}/count.py

if [ $# == 1 ]; then
    rm -rf ${TRACEDIR}/*-result
    exit
fi
make clean
make

for file in ${TRACEDIR}/tr-*.ref; do
    OUTPUTFILE=${file}-result
    rm -rf ${OUTPUTFILE}
    echo "Algorithm, Memory size,Hit rate,Hit count,Miss count,Overall eviction count,Clean eviction count,Dirty eviction count" >> ${OUTPUTFILE}
    SWAPCOUNT=`python ${COUNTER} ${file}` 
    echo "running on ${file}"
    for algo in fifo rand lru clock; do
        printf "%s" "$algo" >> ${OUTPUTFILE}
        echo "  running on ${algo}"
        for memsize in 50 100 150 200; do 
            echo "      running on ${memsize}"
            printf ",%d," "${memsize}" >> ${OUTPUTFILE}
            ./sim -f ${file} -m ${memsize} -s ${SWAPCOUNT} -a ${algo} >> ${OUTPUTFILE}
        done
    done
done

make clean
