import sys
import os
import time
from time import gmtime, strftime, localtime

import numpy as np

import json
import csv

import zwg3m

import pem
import re
import base64
import asn1

import math
#import crypto



#===============================================================================
G3_INS_RD = '80'           
G3_INS_WR = '81'            
G3_INS_VP = '82'            
G3_INS_CP = '83'            
G3_INS_WR_P2_UP_PT  = '00'  

G3_INS_WR_P2_LO_SA  = '00'  
G3_INS_WR_P2_LO_KA  = '01'  
G3_INS_WR_P2_LO_DA0 = '02'  
G3_INS_WR_P2_LO_DA1 = '03'  

G3_INS_WR_LEN = 72



#===============================================================================
json_certi = './certi.json'
json_zwg3m = './zwg3m.json'



#===============================================================================
def main():
 
  #--- Connect to ZWG3M --------------------------------------------------------
  dev = zwg3m.zwg3m()
  pl = dev.getList()

  if len(pl)<1:
    print("Error : Cannot find COM port")
    sys.exit(1)
     
  os.chdir(os.path.dirname(os.path.realpath(__file__)))    

  if os.path.isfile(json_certi) == False:
    print("Error : Cannot find certi.json")
    sys.exit(1)

   
  Port = None
  if os.path.isfile(json_zwg3m) == True:
    with open(json_zwg3m, mode='r') as jf:
      Port = json.loads(json.load(jf))['Port']

      if Port in [x[0] for x in pl]:
        pass
      else:
        Port = None

  if Port == None:
    for n in range(len(pl)):
      print('{}: {}'.format(n, pl[n]))
    print('\n')
    n = int(input('Select Port:  '))
    dev.open(pl[n][0])

    data = {'Port':'{}'.format(pl[n][0])}
    jdata = json.dumps(data, indent=2)
    with open(json_zwg3m, mode='w') as jf:
      json.dump(jdata, jf, indent=2)
  else:
    dev.open(Port)
  

  #--- JSON --------------------------------------------------------------------  
  with open(json_certi, mode='r') as jf_certi:
    jf_certi_data = json.load(jf_certi)

    fn_aws_root_ca = jf_certi_data["AWS ROOT CA"]
    fn_user_priv_key = jf_certi_data["USER KEY"]      
    fn_user_cert = jf_certi_data["USER CERT"]    
    g3_password = jf_certi_data["G3 PASSWORD"]

    if os.path.isfile(fn_aws_root_ca) == False:
      print("Error : Cannot find AWS ROOT CA")
      sys.exit(1)
    if os.path.isfile(fn_user_priv_key) == False:
      print("Error : Cannot find USER PRIVATE KEY")
      sys.exit(1) 
    if os.path.isfile(fn_user_cert) == False:
      print("Error : Cannot find USER CERTIFICATE")
      sys.exit(1) 


  #--- PASSWORD ----------------------------------------------------------------
  print('\n~~~~~~~~~~ PASSWORD ~~~~~~~~~~~~')
  G3_INS_Code = G3_INS_VP
  G3_P1 = 0
  G3_P2_H = 0
  G3_P2_L = 0
  G3_DATA = g3_password

  packet = '{}{:02x}{:02x}{:02x}{}'.format(G3_INS_Code, G3_P1, G3_P2_H, G3_P2_L, G3_DATA).upper()
  #if G3_INS_WR_LEN != len(packet):
  #  print("G3 Command : Invalid Packet Length")
  #print(packet)
  dev.g3_cmd(packet, "\n G3(1/4)-Verifying PASSWORD \n")
  time.sleep(2.0)


  #--- USER CERT KEY -----------------------------------------------------------
  print('\n~~~~~~~~~~ USER KEY ~~~~~~~~~~~~')
  if os.path.isfile(fn_user_priv_key) == True:
    with open(fn_user_priv_key, mode='r') as f_user_key:

      lines = f_user_key.readlines()
      
      base64_user_pri_key = ''
      _start = 0
      _end = 0
      for line in lines:
        if line == '-----BEGIN EC PRIVATE KEY-----\n':
          _start = 1
        elif line == '-----END EC PRIVATE KEY-----\n':
          _end = 1
          break
        elif _start == 1 and _end == 0:
          base64_user_pri_key = base64_user_pri_key + line
        else:
          pass
        #print(line)

      #print(base64_user_pri_key)
      unit_len = 32*2
      hex_user_pri_key = base64.b64decode(base64_user_pri_key).hex()
      hex_user_pri_key = hex_user_pri_key[14:14+unit_len] 
      hex_user_pri_key = hex_user_pri_key.upper()
      
      #print(hex_user_pri_key)

      
      G3_INS_Code = G3_INS_WR
      G3_P1 = 114
      G3_P2_H = G3_INS_WR_P2_UP_PT
      G3_P2_L = G3_INS_WR_P2_LO_KA
      G3_DATA = hex_user_pri_key

      packet = '{}{:02x}{}{}{:0<64}'.format(G3_INS_Code, G3_P1, G3_P2_H, G3_P2_L, G3_DATA).upper()
      if G3_INS_WR_LEN != len(packet):
        print("G3 Command : Invalid Packet Length")
      #print(packet)
      dev.g3_cmd(packet,"\n G3(2/4)-Writing USER PRIVATE KEY \n")

      # ???
      temp = int(len(hex_user_pri_key)/2)
      if temp % 32 != 0:
        sec_len = int((int(temp/3) + 1) * 32)
      else:
        sec_len = int(temp)
      sec_start = G3_P1
      sec_end = int(sec_start + sec_len%32)
      priInfo = '{:04x}{:02x}{:02x}'.format(sec_len, sec_start, sec_end)
      #print(sec_len, sec_start, sec_end)

      f_user_key.close()
      time.sleep(2.0)
      print('\n writing key - done \n')

  #--- USER CERTI --------------------------------------------------------------
  print('\n~~~~~~~~~~ USER CERTI ~~~~~~~~~~~~')
  if os.path.isfile(fn_user_cert) == True:
    with open(fn_user_cert, mode='r') as f_user_cert:
      lines = f_user_cert.readlines()
      base64_user_cert = ''
      _start = 0
      _end = 0      
      for line in lines:
        if line == '-----BEGIN CERTIFICATE-----\n':
          _start = 1
        elif line == '-----END CERTIFICATE-----\n':
          _end = 1
          break
        elif _start == 1 and _end == 0:
          base64_user_cert = base64_user_cert + line
        else:
          pass

      hex_user_cert = base64.b64decode(base64_user_cert).hex()

      unit_len = 32*2
      array_user_cert = [hex_user_cert[i:i+unit_len] for i in range(0, len(hex_user_cert), unit_len)]

      G3_INS_Code = G3_INS_WR
      G3_P1_Base = 0
      G3_P2_H = G3_INS_WR_P2_UP_PT
      G3_P2_L = G3_INS_WR_P2_LO_DA1

      sec_len = 0
      sec_start = G3_P1_Base

      for idx, unit in enumerate(array_user_cert):
        #if unit_len != len(unit):
        #  unit = unit.ljust(unit_len, '0')
        unit = unit.upper()
        #print(idx, unit)

        G3_P1 = G3_P1_Base + idx
        G3_DATA = unit

        packet = '{}{:02x}{}{}{:0<64}'.format(G3_INS_Code, G3_P1, G3_P2_H, G3_P2_L, G3_DATA).upper()
        if G3_INS_WR_LEN != len(packet):
          print("G3 Command : Invalid Packet Length")        
        #print(packet)
        dev.g3_cmd(packet, "\n G3(3/4)-Writing USER CERTI block"+ str(idx))

        sec_len = (idx + 1) * 32
        sec_end = sec_start + idx

      certInfo = '{:04x}{:02x}{:02x}'.format(sec_len, sec_start, sec_end)
      #print(sec_len, sec_start, sec_end)

      f_user_cert.close()
      time.sleep(2.0)
      print('\n writing certificate - done \n')

    #--- USER PROFILE ------------------------------------------------------------
    G3_PRF_OPT = 2                
    G3_PRF_DSC = 'The client key' # Description
    G3_PRF_SN  = 5                
    G3_PRF_KU  = 17               
    G3_PRF_KS  = 0               
    G3_PRF_KT  = 48               
    G3_PRF_KI  = priInfo          
    G3_PRF_CI  = certInfo
    G3_PRF_PF = 153
    packet = '{:x},{},{:02x},{:02x},{:02x},{:02x},{},{},{:x}'.format(G3_PRF_OPT, G3_PRF_DSC, G3_PRF_SN, G3_PRF_KU, G3_PRF_KS, G3_PRF_KT, G3_PRF_KI, G3_PRF_CI, G3_PRF_PF).upper()
    #print(packet)
    dev.g3_profile(packet)
    time.sleep(1.0)

  #--- AWS ROOT CA -------------------------------------------------------------
  print('\n~~~~~~~~~~ AWS ROOT CA ~~~~~~~~~~~~')
  if os.path.isfile(fn_aws_root_ca) == True:
    with open(fn_aws_root_ca, mode='r') as f_aws:

      lines = f_aws.readlines()

      base64_aws_root_ca = ''
      _start = 0
      _end = 0            
      for line in lines:
        if line == '-----BEGIN CERTIFICATE-----\n':
          _start = 1
        elif line == '-----END CERTIFICATE-----\n':
          _end = 1
          break
        elif _start == 1 and _end == 0:
          base64_aws_root_ca = base64_aws_root_ca + line
        else:
          pass          

      hex_aws_root_ca = base64.b64decode(base64_aws_root_ca).hex()

      unit_len = 32*2
      array_aws_root_ca = [hex_aws_root_ca[i:i+unit_len] for i in range(0, len(hex_aws_root_ca), unit_len)]

      G3_INS_Code = G3_INS_WR
      G3_P1_Base = G3_P1 + 1
      G3_P2_H = G3_INS_WR_P2_UP_PT
      G3_P2_L = G3_INS_WR_P2_LO_DA1

      sec_len = 0
      sec_start = G3_P1_Base

      for idx, unit in enumerate(array_aws_root_ca):
        #if unit_len != len(unit):
        #  unit = unit.ljust(unit_len, '0')
        unit = unit.upper()
        #print(unit)
        #print(type(unit))
        G3_P1 = G3_P1_Base + idx
        G3_DATA = unit

        packet = '{}{:02x}{}{}{:0<64}'.format(G3_INS_Code, G3_P1, G3_P2_H, G3_P2_L, G3_DATA).upper()
        if G3_INS_WR_LEN != len(packet):
          print("G3 Command : Invalid Packet Length")        
        #print(packet)
        dev.g3_cmd(packet, "\n G3(4/4)-Writing AWS ROOT CA "+ str(idx))

        sec_len = (idx + 1) * 32
        sec_end = sec_start + idx


      certInfo = '{:04x}{:02x}{:02x}'.format(sec_len, sec_start, sec_end)

      #print(sec_len, sec_start, sec_end)

      f_aws.close()
      time.sleep(2.0)

      print('\n writing AWS root CA - done \n')
    #--- USER PROFILE ------------------------------------------------------------
    G3_PRF_OPT = 2                
    G3_PRF_DSC = 'The key for CA' # Description
    G3_PRF_SN  = 6                
    G3_PRF_KU  = 1                 
    G3_PRF_KS  = 0                
    G3_PRF_KT  = 48               
    G3_PRF_KI  = 0          
    G3_PRF_CI  = certInfo
    G3_PRF_PF = 153
    packet = '{:x},{},{:02x},{:02x},{:02x},{:02x},{:0<8x},{},{:x}'.format(G3_PRF_OPT, G3_PRF_DSC, G3_PRF_SN, G3_PRF_KU, G3_PRF_KS, G3_PRF_KT, G3_PRF_KI, G3_PRF_CI, G3_PRF_PF).upper()
    #print(packet)
    dev.g3_profile(packet)
    time.sleep(1.0)
    print('\n G3 profile write - done \n')

#===============================================================================
if __name__ == "__main__":
  main()
