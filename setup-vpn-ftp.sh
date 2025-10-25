#!/bin/bash

# Скрипт установки VPN и FTP серверов
# IP сервера: 194.34.238.178

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# IP сервера
SERVER_IP="194.34.238.178"

# Проверка прав root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Пожалуйста, запустите скрипт с правами root: sudo ./script.sh${NC}"
    exit 1
fi

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[ПРЕДУПРЕЖДЕНИЕ] $1${NC}"
}

error() {
    echo -e "${RED}[ОШИБКА] $1${NC}"
}

# Обновление системы
log "Обновление пакетов системы..."
apt update && apt upgrade -y

# Установка необходимых пакетов
log "Установка необходимых пакетов..."
apt install -y openvpn easy-rsa wireguard vsftpd ufw net-tools curl

# Настройка OpenVPN
setup_openvpn() {
    log "Настройка OpenVPN..."
    
    # Копируем easy-rsa
    cp -r /usr/share/easy-rsa/ /etc/openvpn/easy-rsa
    cd /etc/openvpn/easy-rsa
    
    # Инициализация PKI
    ./easyrsa init-pki
    echo "ca" | ./easyrsa build-ca nopass
    echo "server" | ./easyrsa gen-req server nopass
    echo "yes" | ./easyrsa sign-req server server
    ./easyrsa gen-dh
    
    # Генерация TLS ключа
    openvpn --genkey --secret ta.key
    
    # Генерация клиентского сертификата
    echo "client" | ./easyrsa gen-req client nopass
    echo "yes" | ./easyrsa sign-req client client
    
    # Создание конфигурации сервера
    cat > /etc/openvpn/server.conf << EOF
port 1194
proto udp
dev tun
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key /etc/openvpn/easy-rsa/pki/private/server.key
dh /etc/openvpn/easy-rsa/pki/dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
tls-auth /etc/openvpn/easy-rsa/ta.key 0
cipher AES-256-CBC
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
verb 3
explicit-exit-notify 1
EOF
    
    # Включение IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    
    # Создание клиентского конфига
    mkdir -p /etc/openvpn/client-configs
    cat > /etc/openvpn/client-configs/client.ovpn << EOF
client
dev tun
proto udp
remote $SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
verb 3
<ca>
$(cat /etc/openvpn/easy-rsa/pki/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/easy-rsa/pki/issued/client.crt)
</cert>
<key>
$(cat /etc/openvpn/easy-rsa/pki/private/client.key)
</key>
<tls-auth>
$(cat /etc/openvpn/easy-rsa/ta.key)
</tls-auth>
EOF
    
    log "OpenVPN настроен"
}

# Настройка WireGuard
setup_wireguard() {
    log "Настройка WireGuard..."
    
    # Генерация ключей для сервера
    cd /etc/wireguard
    umask 077
    wg genkey | tee server_privatekey | wg pubkey > server_publickey
    
    # Генерация ключей для клиента
    wg genkey | tee client_privatekey | wg pubkey > client_publickey
    
    # Создание конфигурации сервера
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $(cat server_privatekey)
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = $(cat client_publickey)
AllowedIPs = 10.0.0.2/32
EOF
    
    # Создание клиентского конфига
    cat > /etc/wireguard/client.conf << EOF
[Interface]
PrivateKey = $(cat client_privatekey)
Address = 10.0.0.2/24
DNS = 8.8.8.8

[Peer]
PublicKey = $(cat server_publickey)
Endpoint = $SERVER_IP:51820
AllowedIPs = 0.0.0.0/0
EOF
    
    log "WireGuard настроен"
}

# Настройка FTP
setup_ftp() {
    log "Настройка FTP сервера..."
    
    # Резервное копирование конфига
    cp /etc/vsftpd.conf /etc/vsftpd.conf.backup
    
    # Создание пользователя FTP
    if id "ftpuser" &>/dev/null; then
        warning "Пользователь ftpuser уже существует"
    else
        useradd -m -d /home/ftpuser -s /bin/bash ftpuser
        echo "ftpuser:$(openssl rand -base64 12)" | chpasswd
        log "Создан пользователь ftpuser с автоматическим паролем"
    fi
    
    # Настройка vsftpd
    cat > /etc/vsftpd.conf << EOF
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
xferlog_file=/var/log/vsftpd.log
xferlog_std_format=YES
chroot_local_user=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO
pasv_min_port=40000
pasv_max_port=50000
user_sub_token=\$USER
local_root=/home/\$USER
pasv_address=$SERVER_IP
EOF
    
    # Создание директории и настройка прав
    mkdir -p /home/ftpuser
    chown ftpuser:ftpuser /home/ftpuser
    chmod 755 /home/ftpuser
    
    log "FTP сервер настроен"
}

# Настройка фаервола
setup_firewall() {
    log "Настройка фаервола..."
    
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Открываем порты
    ufw allow ssh
    ufw allow 1194/udp
    ufw allow 51820/udp
    ufw allow 21/tcp
    ufw allow 20/tcp
    ufw allow 40000:50000/tcp
    
    # Включаем NAT
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    
    ufw --force enable
    log "Фаервол настроен"
}

# Запуск сервисов
start_services() {
    log "Запуск сервисов..."
    
    systemctl enable openvpn@server
    systemctl start openvpn@server
    
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    systemctl enable vsftpd
    systemctl restart vsftpd
    
    log "Все сервисы запущены"
}

# Создание клиентских файлов
create_client_files() {
    log "Создание клиентских файлов..."
    
    mkdir -p /root/vpn-configs
    
    # OpenVPN клиентский файл
    cp /etc/openvpn/client-configs/client.ovpn /root/vpn-configs/
    
    # WireGuard клиентский файл
    cp /etc/wireguard/client.conf /root/vpn-configs/
    
    # Создание QR-кода для WireGuard
    if command -v qrencode &> /dev/null; then
        apt install -y qrencode
        qrencode -t ansiutf8 < /etc/wireguard/client.conf
        qrencode -o /root/vpn-configs/wireguard-qr.png < /etc/wireguard/client.conf
    fi
    
    # Информация для пользователя
    cat > /root/vpn-configs/README.txt << EOF
VPN КОНФИГУРАЦИИ

Сервер: $SERVER_IP

OpenVPN:
- Файл: client.ovpn
- Порт: 1194/udp
- Для использования: импортировать в OpenVPN клиент

WireGuard:
- Файл: client.conf  
- Порт: 51820/udp
- Для использования: отсканировать QR код или импортировать в WireGuard клиент

FTP:
- Сервер: $SERVER_IP
- Пользователь: ftpuser
- Пароль: $(grep ftpuser /etc/shadow | cut -d: -f2)
- Порт: 21
- Режим: Passive (пассивный)

ВАЖНО:
1. Сохраните эти файлы в безопасном месте
2. Для FTP рекомендуется сменить пароль пользователя ftpuser
3. Файлы конфигураций находятся в /root/vpn-configs/
EOF

    log "Клиентские файлы созданы в /root/vpn-configs/"
}

# Основная функция
main() {
    log "Начало установки VPN и FTP серверов на сервер $SERVER_IP..."
    
    setup_openvpn
    setup_wireguard
    setup_ftp
    setup_firewall
    start_services
    create_client_files
    
    log "Установка завершена!"
    echo ""
    echo "=== ИНФОРМАЦИЯ ДЛЯ ПОДКЛЮЧЕНИЯ ==="
    echo "OpenVPN: Используйте файл /root/vpn-configs/client.ovpn"
    echo "WireGuard: Используйте файл /root/vpn-configs/client.conf" 
    echo "FTP: Сервер $SERVER_IP, пользователь ftpuser"
    echo "Пароль FTP: $(grep ftpuser /etc/shadow | cut -d: -f2)"
    echo ""
    echo "QR-код WireGuard:"
    qrencode -t ansiutf8 < /etc/wireguard/client.conf 2>/dev/null || echo "Установите qrencode для просмотра QR-кода"
    echo ""
    echo "Не забудьте сохранить клиентские файлы и сменить пароль FTP!"
}

# Запуск основной функции
main
