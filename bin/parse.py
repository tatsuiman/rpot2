#!/usr/bin/env python
# vim: fileencoding=utf-8
import sys
import re
import os

def main():
    output = '#fields\tindicator\tindicator_type\tmeta.source\tmeta.do_notice\tmeta.if_in\n'
    filename = sys.argv[1]
    print 'parse %s' % filename
    source = os.path.basename(filename).replace('.txt', '').replace('.ipset', '')
    with(open(filename)) as f:
        for line in f:
            line = line.replace('\n', '')
            if line == '':continue
            if line.find('#') == 0:continue
            is_valid = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", line)
            if is_valid:
                output += '%s\tIntel::ADDR\t%s\tT\t-\n' % (line, source)
            else:
                if line.find('/') != -1:
                    output += '%s\tIntel::URL\t%s\tT\t-\n' % (line, source)
                else:
                    output += '%s\tIntel::DOMAIN\t%s\tT\t-\n' % (line, source)
    with(open(filename, 'w')) as f:
        f.write(output)

if __name__ == '__main__':
    main()
