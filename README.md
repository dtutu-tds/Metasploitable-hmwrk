# Домашнее задание к занятию «Уязвимости и атаки на информационные системы»

**Студент:** Тутубалин Дмитрий

---

## Задание 1

Скачайте и установите виртуальную машину Metasploitable: https://sourceforge.net/projects/metasploitable/.

Это типовая ОС для экспериментов в области информационной безопасности, с которой следует начать при анализе уязвимостей.

Просканируйте эту виртуальную машину, используя **nmap**.

Попробуйте найти уязвимости, которым подвержена эта виртуальная машина.

Сами уязвимости можно поискать на сайте https://www.exploit-db.com/.

Для этого нужно в поиске ввести название сетевой службы, обнаруженной на атакуемой машине, и выбрать подходящие по версии уязвимости.

Ответьте на следующие вопросы:

- Какие сетевые службы в ней разрешены?
- Какие уязвимости были вами обнаружены? (список со ссылками: достаточно трёх уязвимостей)
  
*Приведите ответ в свободной форме.*

### Решение

Скачал и запустил Metasploitable в Proxmox. IP адрес 192.168.1.13.

Сделал полное сканирование с определением сервисов:
```bash
sudo nmap -A -p- 192.168.1.13
```

**Найденные сетевые службы (по результату сканирования):**
- FTP (21) — vsftpd 2.3.4
- SSH (22) — OpenSSH 4.7p1 Debian 8ubuntu1
- Telnet (23) — Linux telnetd
- SMTP (25) — Postfix (уязвим SSL/TLS: POODLE, слабые DH)
- DNS (53) — ISC BIND 9.4.2
- HTTP (80) — Apache httpd 2.2.8 (Ubuntu) DAV/2
- RPCBind (111), NFS (2049), mountd, nlockmgr, status — активны RPC‑сервисы
- SMB (445) / NetBIOS-SSN (139) — Samba smbd 3.X–4.X
- exec/login/tcpwrapped (512/513/514)
- Java RMI Registry (1099) — GNU Classpath grmiregistry
- Metasploitable bindshell (1524)
- MySQL (3306) — 5.0.51a-3ubuntu5
- PostgreSQL (5432) — 8.3.0–8.3.7 (SSL/TLS: POODLE, CCS Injection, слабые/анонимные DH)
- VNC (5900)
- X11 (6000)
- IRC (6667) — UnrealIRCd (троянизированная версия)
- Apache JServ AJP13 (8009)
- Apache Tomcat/Coyote (8180)

**Обнаруженные уязвимости (подтверждены NSE):**
1. vsftpd 2.3.4 Backdoor (CVE-2011-2523) — `ftp-vsftpd-backdoor` показал VULNERABLE (root shell) — https://www.exploit-db.com/exploits/17491
2. UnrealIRCd Backdoor — `irc-unrealircd-backdoor` обнаружил троянизированную версию — https://www.exploit-db.com/exploits/16922
3. Java RMI Registry ClassLoader RCE (удалённая загрузка классов) — подтверждено `rmi-vuln-classloader` — https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/java_rmi_server.rb

Дополнительно по TLS/SSL (SMTP/PostgreSQL):
- POODLE (CVE-2014-3566), слабые/анонимные DH группы, CCS Injection (CVE-2014-0224), Slowloris для HTTP на 8180/Tomcat — см. отчёт.

Полный вывод сканирования уязвимостей (Nmap + NSE): [vuln-192.168.1.13.txt](scans/vuln-192.168.1.13.txt)

---

## Задание 2

Проведите сканирование Metasploitable в режимах SYN, FIN, Xmas, UDP.

Запишите сеансы сканирования в Wireshark.

Ответьте на следующие вопросы:

- Чем отличаются эти режимы сканирования с точки зрения сетевого трафика?
- Как отвечает сервер?

*Приведите ответ в свободной форме.*

### Решение

Запустил Wireshark и начал захват трафика на интерфейсе, через который идет связь с Metasploitable.

Выполнил четыре разных типа сканирования:

**SYN сканирование:**
Захват пакетов: [syn_scan.pcapng](captures/syn_scan.pcapng)  
Текстовый отчёт: [scans/syn-scan.txt](scans/syn-scan.txt)

**FIN сканирование:**
Захват пакетов: [fin_scan.pcapng](captures/fin_scan.pcapng)  
Текстовый отчёт: [scans/fin-scan.txt](scans/fin-scan.txt)

**Xmas сканирование:**
Захват пакетов: [xmas_scan.pcapng](captures/xmas_scan.pcapng)  
Текстовый отчёт: [scans/xmas-scan.txt](scans/xmas-scan.txt)

**UDP сканирование:**
Захват пакетов: [udp_scan.pcapng](captures/udp_scan.pcapng)  
Текстовый отчёт: [scans/udp-scan.txt](scans/udp-scan.txt)

**Отличия в сетевом трафике:**

- **SYN** - отправляет TCP SYN пакет, ждет SYN/ACK (открыт) или RST (закрыт)
- **FIN** - отправляет TCP FIN без установки соединения, открытые порты молчат, закрытые отвечают RST
- **Xmas** - отправляет пакет с флагами FIN+PSH+URG (как елка), работает похоже на FIN
- **UDP** - отправляет UDP пакеты, ждет ICMP "port unreachable" (закрыт) или тишину (открыт)

**Ответы сервера:**
- SYN: стандартные TCP ответы
- FIN/Xmas: нестандартное поведение, может обходить некоторые файрволы
- UDP: зависит от сервиса и настроек

В Wireshark видно, что каждый тип сканирования генерирует разный трафик - от стандартных TCP handshake до необычных комбинаций флагов.