import json
import random
import time
import sys
import logging
import requests
import traceback

def random_privs():
    return random.choice(['User', 'Admin'])

def random_os():
    # использует строки из бинаря
    osvers = [
        "Windows Home Server",
        "Windows Server 2003",
        "Windows Server 2008",
        "Windows Server 2008 R2",
        "Windows Server 2012",
        "Windows Server 2012 R2",
        "Windows Server 2019",
        "Windows Server 2022",
        "Windows xp",
        "Windows XP Professional x64 Edition",
        "Windows Vista",
        "Windows 7",
        "Windows 8",
        "Windows 8.1",
        "Windows 10",
        "Windows 11"
    ]

    return random.choice(osvers)

def random_user():
    users = ["alex", "alice", "bob", "user"]
    name = random.choice(users)
    if bool(random.randint(0, 1)):
        name = name.capitalize()

    return name

def make_request(ip, port, params, useragent, proxies):
    headers = {
            'Accept': 'text/*',
            'User-Agent': useragent
    }

    if proxies:
        return requests.get(f'http://{ip}:{port}/c2.php', params=params, headers=headers, proxies=proxies)
    else:
        return requests.get(f'http://{ip}:{port}/c2.php', params=params, headers=headers)


def main():
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s')
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    proxies = {}
    if len(sys.argv) > 1:
        flag = sys.argv[1]
        if flag == '-h' or flag == '--help':
            print(f"Использование: {sys.argv[0]} [-h|--help]|[-p|--proxy <прокси>]")
            print("\t-p,\n\t--proxy - указать прокси для подключения")
            exit(0)
        elif flag == '-p' or flag == '--proxy':
            if len(sys.argv) < 3:
                print("Укажите прокси!")
                exit(-1)
            else:
                proxies['http'] = sys.argv[2]
                proxies['https'] = sys.argv[2]

    cfg = {}
    with open('config.json', 'r') as f:
        cfg = json.load(f)

    ua = cfg["useragent"]
    ip = cfg["ipaddr"]
    port = cfg["port"]

    username = random_user()
    os = random_os()
    priv = random_privs()

    # Регистрация бота
    reg_payload = {
        'action': 'installnewbot',
        'Username': username,
        'OsVersion': os,
        'Privileges': priv
    }

    try:
        r = make_request(ip, port, reg_payload, ua, proxies)
    except Exception as e:
        logger.error("Ошибка подключения: %s", type(e))
        logging.error(traceback.format_exc())
        exit(-1)
    
    botid = r.content
    if r.status_code == 200:
        logger.info("Успешная регистрация! Выданный сервером ID: %s", botid)
    else:
        logger.error("Сервер вернул неожиданный код: %d", r.status_code)
        exit(-1)

    # Запрашиваем команду у сервера
    idle_payload = {
        'action': 'fetchcommand',
        'botid': botid
    }

    while True:
        try:
            r = make_request(ip, port, reg_payload, ua, proxies)
        except Exception as e:
            logger.error("Ошибка запроса: %s", type(e))
            logging.error(traceback.format_exc())
            exit(-1)

        response = r.content
        if r.status_code == 200:
            logger.info("Получен ответ сервера: %s", response.hex())
        else:
            logger.error("Ошибка получения ответа")
            exit(-1)

        time.sleep(1)


if __name__ == '__main__':
    main()

# Алгоритм дешифрования полезной нагрузки я, к сожалению, не успел реализовать.
# Сервер может отправить зашифрованный ответ с командой к скачиванию файла, после чего
# бот его загружает и отпраляет GET-запрос `?action=updatecommand&status=finished&botid=<ID>`.
#
# Подозреваю, что не отвечающий на запрос клиент может вызвать подозрения у злоумышленника...

