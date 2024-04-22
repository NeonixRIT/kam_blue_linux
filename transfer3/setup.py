import os
from base64 import b64decode


def change_user_passwords(ob_pw: str, ob_pw_len: int) -> None:
    '''
    Change all user passwords except for grey/gray users
    '''
    with open('/etc/passwd', 'r') as f:
        for user_line in f:
            user_line = user_line.strip()
            username = user_line.split(':')[0]
            if 'grey' in username.lower() or 'gray' in username.lower():
                continue
            os.system(f"echo '{username}:{b64decode(int(ob_pw, 16).to_bytes(ob_pw_len, byteorder='big')).decode()}' | chpasswd")


def disable_unknown_users(known_usernames: list[str]) -> None:
    '''
    Change all user passwords except for grey/gray users
    '''
    with open('/etc/passwd', 'r') as f:
        for user_line in f:
            user_line = user_line.strip()
            username = user_line.split(':')[0]
            if 'grey' in username.lower() or 'gray' in username.lower():
                continue
            if username.lower() not in [uname.lower() for uname in known_usernames]:
                os.system(f"usermod -L {username}")
            else:
                os.system(f"usermod -U {username}")


def run_commands(commands_list: list[str]) -> None:
    for command in commands_list:
        os.system(command)


def main():
    change_user_passwords('4d4441774e413d3d', 8)

    commands_list = [
        'unalias -a', # remove all aliases
        'chattr -i /etc/hosts', # make sure /etc/hosts is not immutable
        'echo "127.0.1.1  $(whoami)" >> /etc/hosts', # add username to /etc/hosts for sudo dns resolve
        'echo "127.0.1.1  $(hostname)" >> /etc/hosts', # add hostname to /etc/hosts for sudo dns resolve
        'find /var/log/ -exec chattr +a {} +', # make all files in /var/log/ append only
        'chattr +i /etc/hosts', # make /etc/hosts immutable
        'cp ./files/usr/lib/x86_64-linux-gnu/libnetfilter_queue.so.1 /usr/lib/x86_64-linux-gnu/', # copy libnetfilter_queue.so.1 for proxy
        'cp ./files/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so /usr/lib/x86_64-linux-gnu/',
        'cp ./files/usr/sbin/xtables-nft-multi /usr/sbin/', # copy xtables-nft-multi for proxy (iptables)
        'cp ./files/.bashrc ~/.bashrc', # copy default bashrc
        'cp ./files/.profile ~/.profile', # copy default profile
        'cp ./files/.bash_logout ~/.bash_logout', # copy default bash_logout
        'cp -r ./files/etc/chkrootkit/ /etc/chkrootkit/', # copy chkrootkit files 1
        'cp -r ./files/usr/lib/chkrootkit/ /usr/lib/chkrootkit/', # copy chkrootkit files 2
        'cp ./files/usr/sbin/chkrootkit /usr/sbin/chkrootkit', # copy chkrootkit binary
        'cp ./files/usr/bin/strings /usr/bin/', # copy strings binary for chrootkit
        'chmod +x /usr/bin/strings', # make strings binary executable
        'chmod +x /usr/sbin/chkrootkit', # make chkrootkit binary executable
        'chmod +x /usr/lib/chkrootkit/*', # make chkrootkit scripts executable
        'chmod +x /usr/sbin/xtables-nft-multi', # make xtables-nft-multi executable
        'chmod +x ./files/lynis/lynis', # make lynis binary executable
        'cp -r ./files/usr/lib/x86_64-linux-gnu/security/ /usr/lib/x86_64-linux-gnu/security/', # copy security files
    ]
    run_commands(commands_list)
    disable_unknown_users(['root', 'grievous', 'sevander', 'yularen', 'titus', 'meero', 'Grey_Team'])


if __name__ == '__main__':
    main()
