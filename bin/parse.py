#!/usr/bin/env python
# vim: fileencoding=utf-8
import sys
import re
import os

def main():
    output_domain = ''
    output_ip = ''
    filename = sys.argv[1]
    output_file = sys.argv[2]
    print 'parse %s' % filename
    source = os.path.basename(filename).replace('.txt', '').replace('.ipset', '')
    with(open(filename)) as f:
        for line in f:
            line = line.replace('\n', '')
            if line == '':continue
            if line.find('#') == 0:continue
            is_valid = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", line)
            if is_valid:
                output_ip += '"%s","%s"\n' % (line, source)
            else:
                if line.find('/') == -1:
                    output_domain += '"%s","%s"\n' % (line, source)

    if output_domain:
        with(open("%s-domain.csv" % output_file, 'a')) as f:
            f.write(output_domain)
    if output_ip:
        with(open("%s-ip.csv" % output_file, 'a')) as f:
            f.write(output_ip)

if __name__ == '__main__':
    main()
