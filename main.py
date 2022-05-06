import datetime
import os.path as path
import argparse
import json
import random
import re
import sys
import time


import paramiko as paramiko


def pass_generator(n):
    lst1 = list(range(65, 91))
    lst2 = list(range(97, 123))
    lst3 = list(range(10))
    lst4 = ['+', '-', '=', '@', '#', '$', '%', '^']
    s1 = ''.join(chr(c) for c in lst1)
    s2 = ''.join(chr(c) for c in lst2)
    s3 = ''.join(str(i) for i in lst3)
    s4 = ''.join(c for c in lst4)
    #s5 = ''.join(c for c in lst4)
    s = s1 + s2 + s3 + s4 # + s5
    p = ''
    for _ in range(n):
        p += random.choice(s)
    return p


def create_parser():
    parser = argparse.ArgumentParser(description='Создание пользователей на удаленном сервере.')
    parser.add_argument('-s', '--server',
                        help='IP сервера на котором нужно создать пользователей. [x.x.x.x или x.x.x.x:port]')  # required=True
    parser.add_argument('-l', '--login',
                        help='Логин пользователя под которым необходимо подключится к '  # required=True
                             'серверу')
    parser.add_argument('-p', '--password', help='Пароль пользователя под которым необходимо '  # required=True
                                                 'подключится к серверу')
    parser.add_argument('-f', '--file', default='users.json', help='Файл с данными о создаваемых пользователях ['
                                                                   'default=users.json]')
    return parser


def open_file(file):
    print(f"[+] Чтение данных из {file}: ", end="")
    try:
        with open(file, 'r', encoding='utf-8') as f:
            raw = json.load(f)
    except Exception as ex:
        print(f"Ошибка\n\t{ex}")
        sys.exit(-1)
    else:
        print("Успех")
        return raw.get('users')


def connect_server(server, user, passwd):
    ip = server.split(":")
    addr = ip[0]
    if len(ip) == 1:
        port = '22'
    else:
        port = ip[1]
    print(f"[+] Попытка подключения к серверу ip={addr} port={port}: ", end="")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=addr,
                       port=int(port),
                       username=user,
                       password=passwd)  # , pkey=key_file
    except Exception as ex:
        print(f"Ошибка\n\t{ex}")
        sys.exit(-1)
    print(f"Успех")
    client.get_transport()
    return client


def run_command(session, command, passwd):
    #print(command)
    stdin,  stdout, stderr = session.exec_command(command=command, get_pty=True)
    stdin.write(passwd + "\n")
    stdin.flush()
    time.sleep(1)
    if stderr.channel.recv_exit_status() != 0:
        #print(stderr.readlines())
        #print("Error!", stderr.readlines())
        error = stderr.readlines()
        if error:
            return "Error", stderr.readlines()
        else:
            return "Error", stdout.readlines()[1]
    else:
        #print(stdout.readlines())
        #print("Ok!")
        return "Ok", stdout.readlines()


def main(args):
    users = open_file(args.file)
    conn = connect_server(args.server, args.login, args.password)
    work_dict = {}

    command = f'sudo su -c "cat /etc/os-release | grep NAME="'
    res = run_command(conn, command, args.password)
    os = None
    for i in res[1]:
        if re.match('NAME="Ubuntu"', i):
            os = 1
            break
        elif re.match('NAME="CentOS Linux"', i):
            os = 2
            break
        elif re.match('NAME="Debian GNU/Linux"', i):
            os = 2
            break
    if not os:
        print("Неизвестная операционная система!", res[1])
        sys.exit(-1)

    print(f"[+] Изменение файла SSHD:")
    print(f"\t[*] Включение ssh_host_rsa_key: ", end="")
    command = f'sudo su -c \'sed -i "s+HostKey /etc/ssh/ssh_host_ecdsa_key+#HostKey /etc/ssh/ssh_host_ecdsa_key+g" "/etc/ssh/sshd_config"\''
    res = run_command(conn, command, args.password)
    print(res[0], end=", ")
    if res[0] != 'Ok':
        print(f"\t\t[!] {res[1].strip()}")
    command = f'sudo su -c \'sed -i "s+HostKey /etc/ssh/ssh_host_ed25519_key+#HostKey /etc/ssh/ssh_host_ed25519_key+g" "/etc/ssh/sshd_config"\''
    res = run_command(conn, command, args.password)
    print(res[0], end=", ")
    if res[0] != 'Ok':
        print(f"\t\t[!] {res[1].strip()}")
    command = f'sudo su -c \'sed -i "s+#HostKey /etc/ssh/ssh_host_rsa_key+HostKey /etc/ssh/ssh_host_rsa_key+g" "/etc/ssh/sshd_config"\''
    res = run_command(conn, command, args.password)
    print(res[0])
    if res[0] != 'Ok':
        print(f"\t\t[!] {res[1].strip()}")
    print(f"\t[*] Отключение RootLogin: ", end="")
    command = f'sudo su -c \'sed -i "s+#PermitRootLogin prohibit-password+PermitRootLogin no+g" "/etc/ssh/sshd_config"\''
    res = run_command(conn, command, args.password)
    print(res[0], end=", ")
    if res[0] != 'Ok':
        print(f"\t\t[!] {res[1].strip()}")
    command = f'sudo su -c \'sed -i "s+PermitRootLogin yes+PermitRootLogin no+g" "/etc/ssh/sshd_config"\''
    res = run_command(conn, command, args.password)
    print(res[0])
    if res[0] != 'Ok':
        print(f"\t\t[!] {res[1].strip()}")
    command = f'sudo su -c \'sed -i "s+#PermitRootLogin no+PermitRootLogin no+g" "/etc/ssh/sshd_config"\''
    res = run_command(conn, command, args.password)
    print(res[0], end=", ")
    if res[0] != 'Ok':
        print(f"\t\t[!] {res[1].strip()}")
    #print('Ok' if (root_ok1 == 'Ok' and root_ok2 == 'Ok') else f"Error\n\t\t[!] {root_er1}\n\t\t[!] {root_er2}")
    print(f"\t[*] Включение PubkeyAuthentication: ", end="")
    command = f'sudo su -c \'sed -i "s+#PubkeyAuthentication yes+PubkeyAuthentication yes+g" "/etc/ssh/sshd_config"\''
    res = run_command(conn, command, args.password)
    print(res[0])
    if res[0] != 'Ok':
        print(f"\t\t[!] {res[1].strip()}")

    for user in users:
        user_root = False
        user_sudoers = False
        user_keys = ""

        login = user.get('login', None)
        if not login:
            continue
        print(f"[+] Работа с пользователем: {login}")
        command = f'sudo su -c "useradd -m {login}"'
        passwd = pass_generator(10)
        print(f"\t[*] Создание пользователя с логином {login}: ", end="")
        res = run_command(conn, command, args.password)
        print(res[0])
        if res[0] != 'Ok':
            print(f"\t\t[!] {res[1].strip()}")
            continue

        print(f"\t[*] Установка пароля пользователю: ", end="")
        command = f'sudo su -c \'echo -e "{passwd}\n{passwd}" | (passwd {login})\''
        res = run_command(conn, command, args.password)
        print(res[0])
        if res[0] != 'Ok':
            print(f"\t\t[!] {res[1].strip()}")

        work_dict[login] = [{"passwd": passwd}]
        # ROOT привелегии
        if user.get('root', None):
            print(f"\t[*] Добавление пользователю ROOT привелегий: ", end="")
            if os == 1 or os == 3:
                command = f'sudo su -c "usermod -aG sudo {login}"'
            else:
                command = f'sudo su -c "usermod -aG wheel {login}"'
            res = run_command(conn, command, args.password)
            print(res[0])
            if res[0] != 'Ok':
                print(f"\t\t[!] {res[1].strip()}")
            user_root = True

        # Add sudoers
        if user.get('sudoers', None):
            print(f"\t[*] Отключение запроса пароля: ")
            print(f"\t\t[~] Добавление пользователя в каталог sudoers.d: ", end="")
            command = f'sudo su -c "touch /etc/sudoers.d/{login}"'
            res = run_command(conn, command, args.password)
            print(res[0])
            if res[0] != 'Ok':
                print(f"\t\t[!] {res[1].strip()}")
            print(f"\t\t[~] Добавление настроек в файл пользователя в каталоге sudoers.d: ", end="")
            command = f'sudo su -c \'echo -e "{login} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/{login}\''
            res = run_command(conn, command, args.password)
            print(res[0])
            if res[0] != 'Ok':
                print(f"\t\t[!] {res[1].strip()}")
            print(f"\t\t[~] Настройка прав на файл пользователя в каталоге sudoers.d: ", end="")
            command = f'sudo su -c "chmod 440 /etc/sudoers.d/{login}"'
            res = run_command(conn, command, args.password)
            print(res[0])
            if res[0] != 'Ok':
                print(f"\t\t[!] {res[1].strip()}")
            user_sudoers = True

        user_key = user.get('key', None)
        if user_key:
            print(f"\t[*] Добавление RSA ключа пользователя: ")
            print(f"\t\t[~] Создание файла с ключам:  ", end="")
            command = f'sudo su -c "mkdir /home/{login}/.ssh"'
            res = run_command(conn, command, args.password)
            command = f'sudo su -c "touch /home/{login}/.ssh/authorized_keys"'
            res = run_command(conn, command, args.password)
            print(res[0])
            if res[0] != 'Ok':
                print(f"\t\t[!] {res[1].strip()}")
            print(f"\t\t[~] Добавление ключа в файл: ", end="")
            command = f'sudo su -c \'echo -e "{user_key}" > /home/{login}/.ssh/authorized_keys\''
            res = run_command(conn, command, args.password)
            print(res[0])
            if res[0] != 'Ok':
                print(f"\t\t[!] {res[1].strip()}")
            command = f'sudo su -c "chown -R {login}:{login} /home/{login}"'
            run_command(conn, command, args.password)
            command = f'sudo su -c "chmod 0700 /home/{login}/.ssh"'
            run_command(conn, command, args.password)
            command = f'sudo su -c "chmod 644 /home/{login}/.ssh/authorized_keys"'
            run_command(conn, command, args.password)
            user_keys = user_key
        work_dict[login] = {"passwd": passwd, "ROOT": user_root, "SUDOERS": user_sudoers, "USER_KEY": user_keys}

    file_name = args.server + ".txt"
    if path.exists(file_name) and path.isfile(file_name):
        mode = "a"
    else:
        mode = "w"
    print(f"[+] Сохранение в файл {file_name}: ", end="")
    now = datetime.datetime.now().strftime("%d-%m-%Y %H:%M")
    with open(file_name, mode, encoding="UTF-8") as f:
        f.writelines(f"{now}: Учетные данные на сервере {args.server}:\n\n")
        for key in work_dict:
            f.writelines(f"\tЛогин пользователя:\t\t{key}\n")
            f.writelines(f"\tПароль пользователя:\t{work_dict[key].get('passwd')}\n")
            f.writelines(f"\tКлюч пользователя:\t\t{work_dict[key].get('USER_KEY')}\n")
            f.writelines(f"\tROOT права:\t\t\t\t{work_dict[key].get('ROOT')}\n")
            f.writelines(f"\tSUDOERS права:\t\t\t{work_dict[key].get('SUDOERS')}\n")
            f.writelines("\n")
        print('Ok')
    print(f"[+] Перезапуск сервиса SSHD на сервере: ", end="")
    command = f'sudo su -c "systemctl restart sshd"'
    res = run_command(conn, command, args.password)
    print(res[0])
    if res[0] != 'Ok':
        print(f"\t\t[!] {res[1].strip()}")
    print(f"[+] Завершение работы.")


if __name__ == '__main__':
    parser = create_parser()
    args = parser.parse_args()
    main(args)
