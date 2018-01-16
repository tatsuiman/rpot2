#!/usr/bin/env python
# vim: fileencoding=utf-8
import sys
import re
import os
import glob

config1 = """@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
@load base/frameworks/intel
@load frameworks/intel/whitelist

redef Intel::read_files += {
"""

config2 = """
};
"""

def main():
    feeds = sys.argv[1]
    ipset = lambda x: '\t"%s"' % x
    ipsets = []
    for feed in feeds.split(','):
        ipsets += glob.glob(feed)
    ipsets = map(ipset, ipsets)
    config = config1 + ',\n'.join(ipsets) + config2
    print(config)

if __name__ == '__main__':
    main()
