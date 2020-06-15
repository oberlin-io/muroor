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

'''
-e frame.number
-e eth.src
-e eth.dst
'''

t='''sudo tshark
-i eth0
-a duration:4
-T fields
-e frame.time
-e ip.src
-e ip.dst
-e tcp.srcport
-e tcp.dstport
-e ip.proto
-e tcp.flags
-E header=y
-E separator=,
-E quote=d
-E occurrence=f'''
#> {}.csv'''
t=' '.join(t.split('\n'))
#print(t)

while True:
    sp=subprocess.Popen(t, shell=True, stdin=None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    o,e=sp.communicate()
    o=o.decode(encoding='UTF-8')
    df=pd.read_csv(StringIO(o))
    for c in df.columns:
        c1=c.replace('.','_')
        df.rename(columns={c:c1}, inplace=True)
    if df.shape[0]>0:
        print( df.to_string(index=False))
        print('')
        # map protocol labels
        m={6:'pr_tcp',17:'pr_udp',}
        df.ip_proto=df.ip_proto.map(m)
        # filtering out non-tcp? trying to avoid nulls, which turned ports to floats, but should be 0|1... 
        # rethink this
        df=df[df.tcp_srcport.notna()]
        df=df.astype({'tcp_srcport':'int','tcp_dstport':'int'})
        df.tcp_srcport='p_'+df.tcp_srcport.astype('str')
        df.tcp_dstport='p_'+df.tcp_dstport.astype('str')
        # How to handle hex of flags? see
        # https://www.manitonetworks.com/flow-management/2016/10/16/decoding-tcp-flags
        # good description how to read hex
        # Make a dict of all possible packet combos?
        m={'0x00000010': 'f_0x00000010'}#'f_syn',}
        df.tcp_flags=df.tcp_flags.map(m)
        dfs=df.drop(columns='ip_dst')
        dfs['ip']=dfs.ip_src
        dfs['ip_src']=1
        # encode these fields for the source ip
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
        enc=enc.astype({'ip_src':'int32',})
        print(enc.to_string(index=False))
        print('')

