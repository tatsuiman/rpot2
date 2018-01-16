#!/usr/bin/env python
# vim: fileencoding=utf-8
import sys
import re
import os
import glob
from datetime import datetime
from elasticsearch import Elasticsearch
es = Elasticsearch()

def main():
    if len(sys.argv) != 4:
        print('%s [hunting keyword files] [output log filename] [tag name]' % sys.argv[0])
        sys.exit(1)
    index_name = 'bro-*'
    files = sys.argv[1]
    output_log = sys.argv[2]
    tag = sys.argv[3]
    for filename in glob.glob(files):
        source, _ = os.path.splitext(os.path.basename(filename))
        print('load %s' % filename)
        with(open(filename)) as f:
            for line in f:
                line = line.replace('\n', '')
                if line == '':continue
                if line.find('#') == 0:continue
                print('search:%s' % line)
                res = es.search(index=index_name, body={"query": {"multi_match": {"query":line, "fields": ['_all']}}})
                hit_total = res['hits']['total']
                if hit_total:
                    with(open(output_log, 'a')) as l:
                        l.write('ioc:%s, source:%s, hit:%s\n' % (line, source, hit_total))
                    for hit in res['hits']['hits']:
                        tags = hit['_source'].get('tags', [])
                        tags.append(tag)
                        tags = list(set(tags))
                        es.update(index=hit['_index'],doc_type=hit['_type'],id=hit['_id'],
                            body={"doc": {'tags': tags}})

if __name__ == '__main__':
    main()
