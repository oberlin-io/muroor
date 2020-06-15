import subprocess
import pandas as pd
#from time import sleep
#from datetime import datetime as dt
import subprocess
from io import StringIO

tshk=' '.join([
      'sudo tshark',
      '-i eth0',
      '-a duration:4',
      '-T fields',
      '-e frame.number',
      '-e frame.time',
      '-e frame.len',
      #'-e eth.src',
      #'-e eth.dst',
      '-e ip.proto',
      '-e ip.src',
      '-e ip.dst',
      '-e tcp.srcport',
      '-e tcp.dstport',
      '-e tcp.seq',
      '-e tcp.flags',
      #'-e tcp.payload',
      '-e _ws.col.Protocol',
      #'-e frame.protocols',
      '-E header=y',
      '-E separator=,',
      '-E quote=d',
      '-E occurrence=f',
      #'#> {}.csv',
      ])

def get_df(cmd=tshk):
    sp=subprocess.Popen(tshk, shell=True,stdin=None,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    o,e=sp.communicate()
    o=o.decode(encoding='UTF-8')
    df=pd.read_csv(StringIO(o))
    for c in df.columns:
        c1=c.replace('.','_')
        df.rename(columns={c:c1}, inplace=True)
    return df

#add flag map

df=get_df()
