'''
Running tshark ever N seconds,
importing CSV output to Pandas,
transforming IP flow src-dst to only IP,
encoding columns.

#add for each capture, add to a master stored csv file
check file size, somehow append to head and trim tail
per size cut off
'''

import pandas as pd
from time import sleep
from datetime import datetime as dt
import subprocess
from io import StringIO


tshk=['sudo tshark',
    '-i eth0',
    #'-a duration:4',
    '-c 5',
    '-T fields',
    '-e frame.time',
    #'-e frame.number',
    #'-e eth.src',
    #'-e eth.dst',
    '-e ip.src',
    '-e ip.dst',
    '-e tcp.srcport',
    '-e tcp.dstport',
    '-e ip.proto',
    '-e tcp.flags',
    '-E header=y',
    '-E separator=,',
    '-E quote=d',
    '-E occurrence=f',
]

tshk=' '.join(tshk)


while True:
    sp=subprocess.Popen(tshk, shell=True, stdin=None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    o,e=sp.communicate()
    o=o.decode(encoding='UTF-8')
    df=pd.read_csv(StringIO(o))
    if df.shape[0]>0:
        print('='*80)
        # Reformat column names
        for c in df.columns:
            c1=c.replace('.','_')
            df.rename(columns={c:c1}, inplace=True)
        # Check output
        print(df.to_string(index=False))
        print('')
        # Map protocol labels
        m={6:'pr_tcp',17:'pr_udp',}
        df.ip_proto=df.ip_proto.map(m)
        df.tcp_srcport='p_'+df.tcp_srcport.astype('str')
        df.tcp_dstport='p_'+df.tcp_dstport.astype('str')
        # How to handle hex of flags? see
        # https://www.manitonetworks.com/flow-management/2016/10/16/decoding-tcp-flags
        # Make a dict of all possible packet combos?
        # scrap this and hex->dec->str->index
        m={ '0x00000010': 'ack',
            '0x00000011': 'finack',
            '0x00000012': 'synack',
            '0x00000018': 'pshack',
        }
        df.tcp_flags=df.tcp_flags.map(m)
        dfs=df.drop(columns='ip_dst')
        dfs['ip']=dfs.ip_src
        dfs['ip_src']=1
        # Encode these fields for the source ip
        for c in ['tcp_srcport','ip_proto','tcp_flags']:
            dum=pd.get_dummies(dfs[c])
            dfs=dfs.join(dum)
        # Do so for dst ip
        dfd=df.drop(columns='ip_src')
        dfd['ip']=dfd.ip_dst
        dfd=dfd.drop(columns='ip_dst')
        for c in ['tcp_dstport','ip_proto','tcp_flags']:
            dum=pd.get_dummies(dfd[c])
            dfd=dfd.join(dum)
        # Union src and dst
        enc=dfs.append(dfd, sort=True)
        enc=enc.dropna(subset=['ip'])
        enc.fillna(0, inplace=True)
        drop=['tcp_srcport', 'tcp_dstport', 'ip_proto', 'tcp_flags']
        enc=enc.drop(columns=drop)
        print(enc.to_string(index=False))
        print('')

