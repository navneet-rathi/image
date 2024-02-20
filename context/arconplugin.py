#!/usr/bin/env python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
import requests
import json
import os 
import nacl.secret
import nacl.utils
import codecs
import os

import logging


class arconPlugin(object):
    def __init__(self):
        self = self
    def parseEnvVar(self , string):
        start_index = string[:string.rfind('"')].rfind('"')
        end_index = string.rfind('"')
        env_var = string[start_index+1:end_index]
        return env_var



    def getPassword(self,ip,username, service_type):
        logging.basicConfig(filename='ansible_pass.log' , filemode='w', format='%(name)s - %(levelname)s - %(message)s')
        conf = open('/usr/share/ansible/plugins/lookup/config.json')
        #key = b'\xbf\x92\xea40\xc0\x8cv\xb2b\x1e\xfc\xc3y\xed\xa0\xdc@\xbd)\xa3;|\xe2\x93\xdf8\xbb\x96\x0e\x83\xc0'
        #box = nacl.secret.SecretBox(key)
        #lines = conf.read().rstrip().encode("raw_unicode_escape")
        #print(lines)
        #line,_ = codecs.escape_decode(lines,'hex')
        # encrypted = box.encrypt(bytes(message,"utf-8"))
        #print(line)
        #try:
            #decrypted = box.decrypt(line).decode("utf-8")
        #except Exception as e:
            #print("Config Error")
        #print(decrypted)
        data = json.load(conf)
        #print(data['hostipHA']+"/arconToken")
        token = ""
        #return data['hostipHA']+"arconToken"
        try:
            url = data['hostipHA']+"/arconToken"
            payload = 'username='+data['username']+'&password='+data['password']+'&grant_type=password'
            headers = {
              'Content-Type': 'application/x-www-form-urlencoded',
              'User-Agent': 'PostmanRuntime/7.36.0'
            }
            response = requests.request("POST", url, headers=headers, data = payload)
            tokens = json.loads(response.text)
            token = tokens.get("access_token")
        except:
            try:
                url = data['hostipDR']+"/arconToken"
                payload = 'username='+data['username']+'&password='+data['password']+'&grant_type=password'
                headers = {
                  'Content-Type': 'application/x-www-form-urlencoded',
                  'User-Agent': 'PostmanRuntime/7.36.0'
                }

                response = requests.request("POST", url, headers=headers, data = payload, verify=False)
                tokens = json.loads(response.text)
                token = tokens.get("access_token")
            except:
                return "Network Failure"

        #print(token)
        if token != "" :
            try:
                url = data['hostipHA']+"/api/ServicePassword/GetTargetDevicePassKey"
                payload = json.dumps([
                    {
                        "ServerIp" : ip,
                        "ServiceTypeID" : service_type,
                        "UserName" : username, 
                        "DbInstanceName": "",
                        "OpenForHours" : "1"
                    }
                ])
                headers = {
                  'User-Agent': 'PostmanRuntime/7.36.0',
                  'Content-Type': 'application/json',
                  'Authorization': 'Bearer '+token
                }
   
                response = requests.request("POST", url, headers=headers, data=payload, verify=False)
                passd = json.loads(response.text)
                return passd.get("Result")[0].get("Password")
                
            except:
                try:
                    url = data['hostipDR']+"/api/ServicePassword/GetTargetDevicePassKey"

                    payload = json.dumps([
                        {
                            "ServerIp" : ip,
                            "ServiceTypeID" : service_type,
                            "UserName" : username, 
                            "DbInstanceName": "",
                            "OpenForHours" : "1"
                        }
                    ])
                    headers = {
                      'User-Agent': 'PostmanRuntime/7.36.0',
                      'Content-Type': 'application/json',
                      'Authorization': 'Bearer '+token
                    }

                    response = requests.request("POST", url, headers=headers, data=payload, verify=False)
                    passd = json.loads(response.text)
                    return passd.get("Result")[0].get("Password")
                except:
                    
                    return "Network Failure"



# python 3 headers, required if submitting to Ansible
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

display = Display()

DOCUMENTATION = """
    name: Arcon Ansible Plugin
    version_added: "1.2"
    author:
      - Arcon Tech Solutions
    short_description: retrieve password from Arcon PAM
    description:
      - Retrieves keys from Arcon PAM Vault 
"""

class LookupModule(LookupBase):



    def run(self, terms, variables=None, **kwargs):

        #print(terms)
        # lookups in general are expected to both take a list as input and output a list
        # this is done so they work with the looping construct 'with_'.
        ret = []
        pwd = ""
        logging.basicConfig(filename='ansible.log' , filemode='w', format='%(name)s - %(levelname)s - %(message)s')
        logging.warning("Starting with the Ansible implementation")
        # terms=['path=/192.168.1.13//root']
        logging.warning(terms)
        terms = ' '.join(terms)
        parts=terms.split('/')
        ip=parts[1]
        service_type=parts[2]
        username=parts[3]
        logging.warning("IPUser Variable me ye gaya hai: {}".format(ip))
        logging.warning("Service type Variable me ye gaya hai: {}".format(service_type))
        logging.warning("username Variable me ye gaya hai: {}".format(username))
        try:
            arcon = arconPlugin()
            logging.warning("Inside IPUser variable = 2 | this is what will go into fetching the Password for The IP {} and the user {} and the service {}".format(ip, username , service_type))
            pwd = arcon.getPassword(ip,username,service_type)
            
            logging.warning("This is the password returned from the ARCON API {}".format(pwd))
        except:
            raise AnsibleError("could not locate password in PAM for service: %s" % terms)  
        if pwd != "":
            conf = open('/usr/share/ansible/plugins/lookup/config.json')
            data = json.load(conf)
            ansible_execution_path = data["ansible_exe_path"]
            bash_file =ansible_execution_path +  "/.bash_profile"
            file1 = open(bash_file, "a")  # append mode
            #lines = '\nexport {}="{}"'.format(keys[x] , pwd)
            lines = '\nexport ANS_PASSWORD="{}"'.format(pwd)
            file1.write(lines)
            file1.close()
            cmd = "source "+ ansible_execution_path +"/.bash_profile"
            logging.warning("This is the path and the env variable set {}".format(ansible_execution_path))
            os.system(cmd)                        
            if pwd != "Network Failure":
                print("We have build it successfully...!")
                #pwd = "Keys generated successfully."
        else:
            pwd = "Key generation failed."
        return pwd
