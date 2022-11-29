import base64
import socket
import ssl
import time
import zlib
from time import sleep
import sys
import win32evtlogutil
import win32evtlog

# Стандартные настроки сислога
VERSION = 1.8
PORT = 514 #BasePORT
WINPORT = 3515
IP = '77.121.49.52' #BaseIP
COUNT = "2000" #BaseCount
METHOD = 1 #BaseTCP
PER_SEC = 1000
KEY = "suck"
KUCHA = 500
#message = "Test message. Key = QmVza2xldG9jaG5paQ== . Method UDP. Number 12 of 5100."
#КОНЕЦ Стандартные настроки сислога

# СТАРТ Вспомогательные переменные
BUFFER_SIZE = 1024
DELIMITER = "==========================="
# КОНЕЦ Вспомогательные переменные

def toFixed(numObj, digits=0):
    return f"{numObj:.{digits}f}"

# НАЧАЛО ВВОД ПОЛЬЗОВАТЕЛЯ
def USER_INPUT():
    global IP, COUNT, METHOD, PER_SEC, KEY, KUCHA
    print("Test UDP/TCP packets from RuSIEM \n"
          "Verion:"+ str(VERSION) +
          "Add win event generator in 4 option")

    # Ввод пользователя
    print("Test UDP/TCP/WIN_TLS packets \n"
          "Standart port syslog "+str(PORT)+"\n"
          "Standart port win " + str(WINPORT) + "\n" )

    print("Select method \n"
          "*[1] UDP \n"
          " [2] TCP \n"
          " [3] WIN_TLS \n"
          " [4] GEN_WIN \n")
    buff = input()
    if buff != "":  # *1(TCP) // 2(UDP) Выбор метода пользователем
        METHOD = int(buff)
    print("Используется метод - " + str(METHOD))
    print(DELIMITER)

    if (METHOD != 4):
        print("IP назначения:\n"
              "Если пусто - " + IP + "\n")
        buff = input() # Ввод ip (193.169.4.30)
        if buff != "":
            IP = buff
        print("Используется IP - " + IP)
        print(DELIMITER)

    print("\n"
          "Колличество пакетов:"
          "\n Если пусто - " + COUNT)
    buff = input() # Ввод количество пакетов
    if buff != "":
        COUNT = buff
    print("Колличество пакетов - " + COUNT)
    print(DELIMITER)

    print("\n"
          "Колличество в сек:"
          "\n"
          "Если пусто - "+ str(PER_SEC) +" событий/сек")
    buff = input() # Ввод количество пакетов
    if buff != "":
        PER_SEC = int(buff)
    print("Выбрано количество - " + str(PER_SEC) + "с/сек")
    print(DELIMITER)

    if(METHOD == 3):
        print("\n"
              "Пачка из:"
              "\n "
              "Если пусто - "+ str(KUCHA) +" событий в 1 отправке\n\n"
                                           "ВНИМАНИЕ! Лучше использовать кратные числа для корректной работы.\n"
                                           "Пример: \n"
                                           "4000 - EPS\n"
                                           "500 или 400 или 1000 или 2000 - событий в пачке\n")
        buff = input() # Ввод количество пакетов
        if buff != "":
            KUCHA = int(buff)
        print("Выбрано количество - " + str(KUCHA) + " событий в 1 отправке")
        print(DELIMITER)

    print("Ключ для поиска: \n"
          "Если пусто - " + KEY)
    buff = input()
    if buff != "":  # *1(TCP) // 2(UDP) Выбор метода пользователем
        KEY = buff
    print("Ключ - " + KEY+"\n")
    print(DELIMITER)
# КОНЕЦ ВВОД ПОЛЬЗОВАТЕЛЯ

#НАЧАЛО РАБОЧИИ ФУНКЦИИ
def TCP(IP, COUNT, PER_SEC, MESSAGE):
    global BUFFER_SIZE
    print("Start TCP")
    METER = 0
    percent_shower=0
    MESSAGE += "Method TCP. Number "
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, PORT))
    while(int(METER) < int(COUNT)):
        METER += 1
        send_str = MESSAGE + str(METER) + " of " + str(COUNT)+"." + "\r\n"
        s.sendall(send_str.encode("utf-8"))     
        percent = float(toFixed(int(METER)/int(COUNT), 2)) * 100
        if (int(percent)%5 == 0):
            if (int(percent) != percent_shower):
                print(str(int(percent))+"%")
                percent_shower = int(percent)
        if (METER % PER_SEC == 0): sleep(1)
    s.close()
    print("Success!")


def UDP(IP, COUNT, PER_SEC, MESSAGE): #WORK
    print("Start UDP")
    METER = 0
    percent_shower=0
    MESSAGE += "Method UDP. Number "
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while (int(METER) < int(COUNT)):
        METER += 1
        s.sendto(bytes(MESSAGE + str(METER) + " of " + str(COUNT)+".", "utf-8"), (IP, PORT))
        percent = float(toFixed(int(METER)/int(COUNT), 2)) * 100
        if (int(percent)%5 == 0):
            if (int(percent) != percent_shower):
                print(str(int(percent))+"%")
                percent_shower = int(percent)
        if (METER % PER_SEC == 0): sleep(1)
    print("Success!")
    

def WIN_TLS(IP, COUNT, PER_SEC, MESSAGE):
    print('Start WIN_TSL')
    METER = 0
    S_BLOCK = '{"agent":{"id":"ONLY-FOR-RUSIEM-TEST-FOREVER","version":"RuSIEM_test_script_version'+ str(VERSION) +'"},"module":"msevt","item":"synthetic_test", "message":"'
    #S_BLOCK = '{"agent":{"id":"04C61284-B800-4563-BAE9-36FFEE00D505","version":"4.1.12.365"},"module":"msevt","item":"just_test", "message":"'
    E_BLOCK = '"}'
    percent_shower = 0
    MESSAGE += "Method WIN_TLS. Number "
    KUCHA_NUMBER = 0

    #Из кучи создаем кучу из битов
    def make_zip(DATA):
        data_bytes = bytes(DATA, 'utf-8')
        data_zip = zlib.compress(data_bytes)
        len_bytes = (len(data_zip)).to_bytes(4, byteorder='little')
        return len_bytes + data_zip

    #Отправка кучи из битов
    def send_data_windows(data):
        # отправляем событие на сиемку
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
                with context.wrap_socket(sock) as ssock:
                    ssock.connect((IP, WINPORT))
                    ssock.sendall(data)
                    ssock.close()
        except ConnectionError:
            print('Connection error. Try again')
            time.sleep(2)
            send_data_windows(data)

    # Подготовка кучи
    while (int(METER) < int(COUNT)):
        KUCHA_METER = 0
        KUCHA_MESS = "["

        while (int(KUCHA) >= int(KUCHA_METER)): #Создание кучи
            if (KUCHA_METER == KUCHA):
                KUCHA_NUMBER+=1
                break
            if(KUCHA_MESS != "["):
                KUCHA_MESS +=","
            METER += 1
            KUCHA_MESS += S_BLOCK + MESSAGE + str(METER) + " of " + str(COUNT) + " \n\rКуча из " + str(KUCHA) + " сообщений" + E_BLOCK
            KUCHA_METER += 1

            percent = float(toFixed(int(METER) / int(COUNT), 2)) * 100
            if (int(percent) % 5 == 0):
                if (int(percent) != percent_shower):
                    print(str(int(percent)) + "%")
                    percent_shower = int(percent)
            if (METER % PER_SEC == 0): sleep(1)

        KUCHA_MESS += "]"
        #print(KUCHA_MESS)

        print("Отправка кучи номер "+str(KUCHA_NUMBER))

        KUCHA_MESS_BIN = make_zip(KUCHA_MESS)
        send_data_windows(KUCHA_MESS_BIN)


def GEN_WIN( COUNT, PER_SEC, MESSAGE):
    print('Start Generate Win Events')
    METER = 0
    percent_shower = 0
    EVT_APP_NAME = "RuSIEM Gen Event script"
    EVT_ID = 20140  # Got this from another event
    EVT_CATEG = 9876
    EVT_DATA = b"RuSIEM test event"
    while (int(METER) < int(COUNT)):
        METER += 1
        EVT_STRS = ["RuSIEM test event string: " + MESSAGE + " " + str(METER) + " of " + str(COUNT) + ". EPS:" + str(PER_SEC)]
        percent = float(toFixed(int(METER)/int(COUNT), 2)) * 100
        if (int(percent)%5 == 0):
            if (int(percent) != percent_shower):
                print(str(int(percent))+"%")
                percent_shower = int(percent)
        win32evtlogutil.ReportEvent(
            EVT_APP_NAME, EVT_ID, eventCategory=EVT_CATEG,
            eventType=win32evtlog.EVENTLOG_WARNING_TYPE, strings=EVT_STRS,
            data=EVT_DATA)
        if (METER % PER_SEC == 0): sleep(1)
    print("Success!")



#КОНЕЦ РАБОЧИИ ФУНКЦИИ

## НАЧАЛО ПОЛЬЗОВАТЕЛЬСКОЙ ЛОГИКИ
USER_INPUT()
MESSAGE = "Test message. Key = " + KEY + " . "

if METHOD == 1:
    UDP(IP, COUNT, PER_SEC, MESSAGE)

if METHOD == 2:
    TCP(IP, COUNT, PER_SEC, MESSAGE)
print("\nИскать события по ключу " + KEY)

if METHOD == 3:
    WIN_TLS(IP, COUNT, PER_SEC, MESSAGE)

if METHOD == 4:
    GEN_WIN(COUNT, PER_SEC, MESSAGE)

print("\nИскать события по ключу " + KEY)
if (input() != ""):
    exit(0)

## КОНЕЦ ПОЛЬЗОВАТЕЛЬСКОЙ ЛОГИКИ


# Потом и кровью от Славы Бестолочи и стаканом крови от Леши Осипенко