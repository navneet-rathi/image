Last login: Fri Feb 16 15:12:02 on ttys000
navneetrathi@Navneets-MacBook-Pro ~ % ssh root@192.168.1.11
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ED25519 key sent by the remote host is
SHA256:KO3JfyQrNG7c/peXGDgqtJ+Jc7VuHuDOgGjhrwgFOo8.
Please contact your system administrator.
Add correct host key in /Users/navneetrathi/.ssh/known_hosts to get rid of this message.
Offending ECDSA key in /Users/navneetrathi/.ssh/known_hosts:14
Host key for 192.168.1.11 has changed and you have requested strict checking.
Host key verification failed.
navneetrathi@Navneets-MacBook-Pro ~ % ssh-keygen -R 192.168.1.11
# Host 192.168.1.11 found: line 12
# Host 192.168.1.11 found: line 13
# Host 192.168.1.11 found: line 14
/Users/navneetrathi/.ssh/known_hosts updated.
Original contents retained as /Users/navneetrathi/.ssh/known_hosts.old
navneetrathi@Navneets-MacBook-Pro ~ % ssh root@192.168.1.11     
The authenticity of host '192.168.1.11 (192.168.1.11)' can't be established.
ED25519 key fingerprint is SHA256:KO3JfyQrNG7c/peXGDgqtJ+Jc7VuHuDOgGjhrwgFOo8.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:25: 192.168.1.13
    ~/.ssh/known_hosts:51: 192.168.1.16
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.1.11' (ED25519) to the list of known hosts.
root@192.168.1.11's password: 


Permission denied, please try again.
root@192.168.1.11's password: 
Activate the web console with: systemctl enable --now cockpit.socket

Last failed login: Tue Feb 20 16:48:36 IST 2024 from 192.168.1.5 on ssh:notty
There was 1 failed login attempt since the last successful login.
Last login: Tue Feb 20 15:32:12 2024
[root@aap1 ~]# 
[root@aap1 ~]# 
[root@aap1 ~]# 
[root@aap1 ~]# ls
anaconda-ks.cfg                                                         jinja_1.yml
ansible-automation-platform-setup-bundle-2.4-3-aarch64                  jinja.yml
ansible-automation-platform-setup-bundle-2.4-3-aarch64.tar.gz           json2ini.py
ansible.log                                                             pass
ansible.yaml                                                            patching
arconplugin.py                                                          playbook.yml
arcon.yml                                                               play.yml
cffi-1.16.0-cp39-cp39-manylinux_2_17_aarch64.manylinux2014_aarch64.whl  pycparser-2.21-py2.py3-none-any.whl
EE                                                                      PyNaCl-1.5.0-cp36-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.manylinux_2_24_aarch64.whl
EE_arcon                                                                templates
EE_from                                                                 unseal.sh
EE_twilio                                                               vault
Email                                                                   zip
[root@aap1 ~]# cd EE_arcon/
[root@aap1 EE_arcon]# ls
ansible.cfg  bindep.txt  context  execution-environment.yml  images.tar  requirements.txt  requirements.yml  requirements.yml.old
[root@aap1 EE_arcon]# cd context/
[root@aap1 context]# l
-bash: l: command not found
[root@aap1 context]# ls
arconplugin.py  _build  config.json  Containerfile
[root@aap1 context]# vim arconplugin.py 
[root@aap1 context]# 
[root@aap1 context]# ls
arconplugin.py  _build  config.json  Containerfile
[root@aap1 context]# cd ..
[root@aap1 EE_arcon]# ls
ansible.cfg  bindep.txt  context  execution-environment.yml  images.tar  requirements.txt  requirements.yml  requirements.yml.old
[root@aap1 EE_arcon]# cd ..
[root@aap1 ~]# ls
anaconda-ks.cfg                                                         jinja_1.yml
ansible-automation-platform-setup-bundle-2.4-3-aarch64                  jinja.yml
ansible-automation-platform-setup-bundle-2.4-3-aarch64.tar.gz           json2ini.py
ansible.log                                                             pass
ansible.yaml                                                            patching
arconplugin.py                                                          playbook.yml
arcon.yml                                                               play.yml
cffi-1.16.0-cp39-cp39-manylinux_2_17_aarch64.manylinux2014_aarch64.whl  pycparser-2.21-py2.py3-none-any.whl
EE                                                                      PyNaCl-1.5.0-cp36-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.manylinux_2_24_aarch64.whl
EE_arcon                                                                templates
EE_from                                                                 unseal.sh
EE_twilio                                                               vault
Email                                                                   zip
[root@aap1 ~]# cd EE_
EE_arcon/  EE_from/   EE_twilio/ 
[root@aap1 ~]# cd EE_
EE_arcon/  EE_from/   EE_twilio/ 
[root@aap1 ~]# cd EE_from/
[root@aap1 EE_from]# l;s
-bash: l: command not found
-bash: s: command not found
[root@aap1 EE_from]# ls
ansible.cfg  bindep.txt  context  execution-environment.yml  requirements.txt  requirements.yml  requirements.yml.old
[root@aap1 EE_from]# vim context/

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
                                                                                                                                                        1,1           Top
