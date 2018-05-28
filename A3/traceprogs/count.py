import sys


def count(filename):
    addr_set = set()
    fp = open(filename, 'r')
    ln = fp.readline()
    while ln != '':
        s = ln.split(',')[0]
        addr_set.add(s)
        ln = fp.readline()
    print len(addr_set)
    return len(addr_set)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "USAGE: python count.py tracefile"
        print "     tracefile: blocked, matmul, simpleloop, bubble_sort"
        exit()
    fname = sys.argv[1]
    count(fname)
