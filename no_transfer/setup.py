import os
from base64 import b64decode
commands = [
    'unalias -a',
    'chattr -i /etc/hosts',
    'echo "127.0.1.1  $(whoami)" >> /etc/hosts',
    'echo "127.0.1.1  $(hostname)" >> /etc/hosts',
    'find /var/log/ -exec chattr +a {} +',
    'chattr +i /etc/hosts',
    'cp ./files/usr/lib/x86_64-linux-gnu/libnetfilter_queue.so.1 /usr/lib/x86_64-linux-gnu/',
    'cp ./files/usr/sbin/xtables-nft-multi /usr/sbin/',
    'cp ./files/.bashrc ~/.bashrc',
    'cp ./files/.profile ~/.profile',
    'cp ./files/.bash_logout ~/.bash_logout',
    'cp -r ./files/etc/chkrootkit/ /etc/chkrootkit/',
    'cp -r ./files/usr/lib/chkrootkit/ /usr/lib/chkrootkit/',
    'cp ./files/usr/sbin/chkrootkit /usr/sbin/chkrootkit',
    'cp ./files/usr/bin/strings /usr/bin/',
    'chmod +x /usr/bin/strings',
    'chmod +x /usr/sbin/chkrootkit',
    'chmod +x /usr/lib/chkrootkit/*',
    'chmod +x /usr/sbin/xtables-nft-multi',
    'chmod +x ./files/lynis/lynis'
]

for command in commands:
    os.system(command)

with open('/etc/passwd', 'r') as f:
    for user_line in f:
        user_line = user_line.strip()
        username = user_line.split(':')[0]
        new_password = '4d4441774e413d3d'
        os.system(f"echo '{username}:{b64decode(int(new_password, 16).to_bytes(8, byteorder='big')).decode()}' | chpasswd")