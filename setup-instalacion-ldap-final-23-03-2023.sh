#!/bin/bash

### Declarar las Variabes para usar
# http://usuario:contraseña@servidor_proxy:puerto"
Proxy="http://10.10.10.3:3128"                                         
LdapBase="dc=cpicm,dc=hlg,dc=sld,dc=cu"
LdapUri="ldaps://201.220.196.162"
LdapUriPort="636"
adminuser="cn=adminldap,dc=cpicm,dc=hlg,dc=sld,dc=cu"
adminpassword="pass"
domain="cpicm.hlg.sld.cu"


UrlReposNova="http://repo.nova.cu/nova/"
UrlReposUbuntu="http://mirror.hlg.sld.cu/ubuntu"

## Poner aqui el contenido del Certificado server_pem
etc_ldap_ssl_server_pem=$(cat <<"EOF"
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAOmPG3A6zA+DFdjJ
VE9vKEHcYR5LC3a8qwUTHaEUWJUnD67AkWGU5O3mhWMyRLFGzBaRiqFQFCRqDOHX
8XAGHatB04yyQzr7Zp0ibUUNg179etEzTERpOUgCVbb96AbemfHoICrgNd/+gtip
SyBaEtKpoN3Y7XQfEZp3xo9xXnqpAgMBAAECgYBs1m9m4T9uixuHJmrPiXEtH9Fy
GG6DKnBXsQzBn4WYG9fHC52z53q3EhFepHI2WlOIwNHlUjfQsErIg6TTG0Z/P+00
6dyh6t05fOiHVdiDRSXCmqG6BTzKCd3Xdfl4ZhAmU3g0dsavxuAil5L12YCJBD0n
QVIJQ5/s9o/h1bGmMQJBAPyeS2BicbXxKXZlygO2UrM/kuPWtQRBwuTgk/kFtCIA
VtIQyQ6bIhDxAEuJcM3x3yN2RNNMQTTM+d6eaqXp1/MCQQDsr39swYnNuyhHdNpP
Po92s/7vvnh6M2Q=
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIC9TCCAl6gAwIBAgIJAPgdSmA3MsbRMA0GCSqGSIb3DQEBCwUAMIGRMQswCQYD
VQQGEwJDVTEQMA4GA1UECAwHSG9sZ3VpbjEQMA4GA1UEBwwHSG9sZ3VpbjEOMAwG
A1UECgwFQ1BJQ00xDjAMBgNVBAsMBUNQSUNNMRkwFwYDVQQDDBBjcGljbS5obGcu
c2xkLmN1MSMwIQYJKoZIhvcNAQkBFhRicmlhbkBpbmZvbWVkLnNsZC5jdTAeFw0y
MDAyMDgxNzIzMjJaFw0yMTAyMDcxNzIzMjJaMIGRMQswCQYDVQQGEwJDVTEQMA4G
A1UECAwHSG9sZ3VpbjEQMA4GA1UEBwwHSG9sZ3VpbjEOMAwGA1UECgwFQ1BJQ00x
DjAMBgNVBAsMBUNQSUNNMRkwFwYDVQQDDBBjcGljbS5obGcuc2xkLmN1MSMwIQYJ
KoZIhvcNAQkBFhRicmlhbkBpbmZvbWVkLnNsZC5jdTCBnzANBgkqhkiG9w0BAQEF
AAOBjQAwgYkCgYEA6Y8bcDrMD4MV2MlUT28oQdxhHksLdryrBRMdoRRYlScPrsCR

4RPA+Vxlxr7LeSoXczdYbcQG9UKAPM679D4PVZOAz6VI0CnAPOlj2Lg=
-----END CERTIFICATE-----
EOF
)

# Colores
ROJO='\033[0;31m'
VERDE='\033[0;32m'
AMARILLO='\033[0;33m'
AZUL='\033[0;34m'
MAGENTA='\033[0;35m'
CIAN='\033[0;36m'
DEFAULT='\033[0m'


# Función para verificar errores y salir del script si ocurre alguno
function verificar_error {
    if [ $? -ne 0 ]; then
        echo -e "${ROJO}ERROR: Ocurrió un error al ejecutar el comando: $1${DEFAULT}"
        exit 1
    fi
}



#### Configuraciones
echo -e "\e[1;32mEste script es una herramienta muy útil para aquellos que necesitan implementar un sistema de autenticación centralizada contra un servidor LDAP. Una vez que se ejecute, el script realizará una copia de seguridad de los archivos antes de modificarlos, lo que garantiza la seguridad de los datos.\n\n\
\e[1;34mAdemás, el script agregará las fuentes de Windows y también automatizará las particiones que tenga con Windows al inicio. De esta manera, se asegurará de que su sistema operativo funcione de manera más eficiente y sin problemas.\n\n\
\e[1;35mPor si fuera poco, si lo desea, el script también puede quitar el navegador por defecto del sistema y agregar la última versión disponible de Mozilla que se encuentre en el FTP. Esto le permitirá navegar por la web de manera más segura y eficiente.\n\n\
\e[1;33mEn resumen, este script es una herramienta muy útil para aquellos que necesitan un sistema de autenticación centralizado y también desean mejorar la eficiencia y seguridad de su sistema operativo. ¡Espero que te sea de ayuda!\n\n\\n\n\
\e[1;32m\033[4mDebe de Editar el script para agregarle los datos de su red, al principio del mismo se encuentran las variables a usar!\n"

read -p "Presione Enter para continuar..."

#######################################################################################################################
###                                                                                                                 ###
###                                                                                                                 ###
###                                          Configuraciones                                                        ###
###                                                                                                                 ###
###                                                                                                                 ###
#######################################################################################################################

#### Configuraciones de los respositorios
## Configuracion Repositorios NOVA
etc_apt_sources_nova_2021_list=$(cat <<EOF
deb $UrlReposNova 2021 principal extendido
EOF
)

etc_apt_sources_ubuntu_bionic_list=$(cat <<EOF
deb [arch=amd64] $UrlReposUbuntu bionic main multiverse restricted universe
deb [arch=amd64] $UrlReposUbuntu bionic-backports main multiverse restricted universe
deb [arch=amd64] $UrlReposUbuntu bionic-proposed main multiverse restricted universe
deb [arch=amd64] $UrlReposUbuntu bionic-security main multiverse restricted universe
deb [arch=amd64] $UrlReposUbuntu bionic-updates main multiverse restricted universe
EOF
)

## Configuracion Ubuntu  Focal
etc_apt_sources_ubuntu_focal_list=$(cat <<EOF
deb [arch=amd64] $UrlReposUbuntu focal main multiverse restricted universe
deb [arch=amd64] $UrlReposUbuntu focal-backports main multiverse restricted universe
deb [arch=amd64] $UrlReposUbuntu focal-proposed main multiverse restricted universe
deb [arch=amd64] $UrlReposUbuntu focal-security main multiverse restricted universe
deb [arch=amd64] $UrlReposUbuntu focal-updates main multiverse restricted universe
EOF
)

## Configuracion Ubuntu Jammy
etc_apt_sources_ubuntu_jammy_list=$(cat <<EOF
deb [arch=amd64] $UrlReposUbuntu jammy main multiverse restricted universe
deb [arch=amd64] $UrlReposUbuntu jammy-backports main multiverse restricted universe
deb [arch=amd64] $UrlReposUbuntu jammy-proposed main multiverse restricted universe
deb [arch=amd64] $UrlReposUbuntu jammy-security main multiverse restricted universe
deb [arch=amd64] $UrlReposUbuntu jammy-updates main multiverse restricted universe
EOF
)



## Configuracion Ldap
etc_ldap_ldap_conf=$(cat <<EOF
base $LdapBase
uri $LdapUri
port 636
TLS_CACERT /etc/ldap/ssl/server.pem
TIMELIMIT 2
TLS_REQCERT never
EOF
)

## Configuracion PAM common-account
etc_pam_d_common_account=$(cat <<"EOF"
account [success=2 new_authtok_reqd=done default=ignore]  pam_unix.so
account [success=1 default=ignore]      pam_ldap.so
account requisite                       pam_deny.so
account required                        pam_permit.so
EOF
)

## Configuracion PAM common-auth
etc_pam_d_common_auth=$(cat <<"EOF"
auth    [success=2 default=ignore]      pam_unix.so nullok_secure
auth    [success=1 default=ignore]      pam_ldap.so use_first_pass
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
auth	optional						pam_cap.so 
EOF
)

## Configuracion PAM common-password
etc_pam_d_common_password=$(cat <<"EOF"
password	    requisite										pam_cracklib.so retry=3 minlen=8 difok=3
password	    [success=2 default=ignore]	pam_unix.so obscure use_authtok try_first_pass sha512
password        [success=1 user_unknown=ignore default=die]     pam_ldap.so use_authtok try_first_pass
password        requisite                      					pam_deny.so
password        required                        				pam_permit.so
password	    optional	                    				pam_gnome_keyring.so 
EOF
)

## Configuracion PAM common-sessio
etc_pam_d_common_session=$(cat <<"EOF"
session required            pam_mkhomedir.so
session	[default=1]			pam_permit.so
session	requisite			pam_deny.so
session	required			pam_permit.so
session optional			pam_umask.so
session	required			pam_unix.so 
session	optional			pam_ldap.so 
session	optional			pam_systemd.so 
EOF
)


## Configuracion Ldap
etc_ldap_conf=$(cat <<EOF
ssl start_tls
ssl on
tls_cacertdir /etc/ldap/ssl/server.pem

base $LdapBase
uri $LdapUri:$LdapUriPort

rootbinddn $adminuser

ldap_version 3
bind_policy soft
bind_timelimit 2
timelimit 2
scope sub
nss_reconnect_maxsleeptime 8
nss_reconnect_sleeptime 1
nss_initgroups_ignoreusers root
nss_srv_domain $domain
pam_password exop
pam_filter objectclass=posixAccount
pam_login_attribute uid
pam_member_attribute memberUid

nss_base_passwd ou=usuarios,$LdapBase?sub
nss_base_shadow ou=usuarios,$LdapBase?sub
nss_base_passwd ou=equipos,$LdapBase?one
nss_base_shadow ou=equipos,$LdapBase?one
nss_base_group  ou=grupos,$LdapBase?one
EOF
)

## Configuracion Ldap
etc_ldap_secret=$(cat <<EOF
$adminpassword
EOF
)

## Configuracion nslcd
etc_nslcd_conf=$(cat <<EOF
uid nslcd
gid nslcd

uri $LdapUri:$LdapUriPort
base $LdapBase

ldap_version 3

binddn $adminuser
bindpw $adminpassword

ssl off
tls_reqcert never
tls_cacertfile /etc/ldap/ssl/server.pem
EOF
)

## Configuracion nsswitch
etc_nsswitch_conf=$(cat <<"EOF"
passwd:      files ldap [notfound=continue]
shadow:      files ldap [notfound=continue]
group:       files ldap [notfound=continue]
gshadow:     files

hosts:       files dns

networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis
EOF
)


# Función para verificar errores y salir del script si ocurre alguno
function verificar_error {
    if [ $? -ne 0 ]; then
        echo -e "${ROJO}ERROR: Ocurrió un error al ejecutar el comando: $1${DEFAULT}"
        exit 1
    fi
}

echo -e "${CIAN}=========================================="
echo -e "Instalando utilidades básicas"
echo -e "==========================================${DEFAULT}"


# Preguntar al usuario si desea utilizar el proxy
read -p "¿Desea utilizar el proxy? (s/n): " usar_proxy

while [ "$usar_proxy" != "s" ] && [ "$usar_proxy" != "n" ]
do
    echo -e "${ROJO}La opción ingresada no es válida. Intente nuevamente.${DEFAULT}"
    read -p "¿Desea utilizar el proxy? (s/n): " usar_proxy
done

# Si el usuario desea utilizar el proxy, se definen las variables de entorno
if [ "$usar_proxy" == "s" ]; then
    # Variables de entorno para proxy
    export http_proxy="$Proxy"
    export https_proxy="$Proxy"
    echo -e "${AMARILLO}Usando el siguiente proxy:${DEFAULT}"
    echo -e "${CYAN}http_proxy=$http_proxy${DEFAULT}"
    echo -e "${CYAN}https_proxy=$https_proxy${DEFAULT}"
fi





# Verificar que el usuario tenga permisos de superusuario
echo -e "${AMARILLO}Verificando permisos de superusuario${DEFAULT}"
if [ "${UID}" != "0" ]; then
    echo -e "${ROJO}Este script debe ejecutarse como superusuario, root o sudo${DEFAULT}"
    exit 1
fi

# Mostrar los repositorios disponibles
echo -e "${AMARILLO}Repositorios disponibles:${DEFAULT}"
echo -e "${ROJO}1. Nova 2021${DEFAULT}"
echo -e "${ROJO}2. Ubuntu Focal${DEFAULT}"
echo -e "${ROJO}3. Ubuntu Bionic${DEFAULT}"
echo -e "${ROJO}4. Ubuntu Jammy${DEFAULT}"
echo
read -p "Seleccione el repositorio que desea utilizar (1/2/3/4): " repositorio

while [ "$repositorio" != "1" ] && [ "$repositorio" != "2" ] && [ "$repositorio" != "3" ] && [ "$repositorio" != "4" ]
do
    echo -e "${ROJO}La opción ingresada no es válida. Intente nuevamente.${DEFAULT}"
    read -p "Seleccione el repositorio que desea utilizar (1/2/3/4): " repositorio
done

# Hacer una copia de seguridad de la configuración del sources.list
echo -e "${AMARILLO}Haciendo una copia de seguridad de la configuración del sources.list${DEFAULT}"
if [ ! -f /etc/apt/sources.list.ORIGINAL ]; then cp -pn /etc/apt/sources.list{,.ORIGINAL}; fi
verificar_error "cp -pn /etc/apt/sources.list{,.ORIGINAL}"

# Copiar el archivo sources.list correspondiente al repositorio seleccionado
echo -e "${AMARILLO}Copiando el archivo sources.list correspondiente${DEFAULT}"
case $repositorio in

    1) echo "$etc_apt_sources_nova_2021_list" > /etc/apt/sources.list
       verificar_error "echo '$etc_apt_sources_nova_2021_list' > /etc/apt/sources.list";;
    2) echo "$etc_apt_sources_ubuntu_focal_list" > /etc/apt/sources.list
       verificar_error "echo '$etc_apt_sources_ubuntu_focal_list' > /etc/apt/sources.list" ;;
    3) echo "$etc_apt_sources_ubuntu_bionic_list" > /etc/apt/sources.list
       verificar_error "echo '$etc_apt-sources-ubuntu-bionic.list' > /etc/apt/sources.list" ;;
    4) echo "$etc_apt_sources_ubuntu_jammy_list" > /etc/apt/sources.list
       verificar_error "echo '$etc_apt_sources_ubuntu_jammy_list' > /etc/apt/sources.list" ;;
esac


# Borrar el contenido de la carpeta /etc/apt/sources.list.d/
echo -e "${AMARILLO}Borrando el contenido de la carpeta /etc/apt/sources.list.d/${DEFAULT}"
rm -f /etc/apt/sources.list.d/*

# Actualizar el sistema y los paquetes
echo -e "${AMARILLO}Actualizando el sistema y los paquetes${DEFAULT}"
apt-get update
verificar_error "apt-get update"
apt-get -y full-upgrade
verificar_error "apt-get -y full-upgrade"

# Instalar el software necesario
echo -e "${AMARILLO}Instalando el software necesario${DEFAULT}"
DEBIAN_FRONTEND=noninteractive apt-get -y install mc libnss-ldapd libpam-ldap libpam-cracklib doublecmd-gtk
verificar_error "DEBIAN_FRONTEND=noninteractive apt-get -y install mc libnss-ldapd libpam-ldap libpam-cracklib doublecmd-gtk"

# Eliminar dependencias y limpiar la caché
echo -e "${AMARILLO}Eliminando dependencias y limpiando la caché${DEFAULT}"
apt-get -y autoremove --purge
verificar_error "apt-get -y autoremove --purge"
apt-get -y clean
verificar_error "apt-get -y clean"

# Establecer la zona horaria
echo -e "${AMARILLO}Estableciendo la zona horaria${DEFAULT}"
timedatectl set-timezone America/Havana
verificar_error "timedatectl set-timezone America/Havana"

# Habilitar la sincronización por NTP
echo -e "${AMARILLO}Habilitando la sincronización por NTP${DEFAULT}"
timedatectl set-ntp true
verificar_error "timedatectl set-ntp true"

echo -e "${AMARILLO}Configuramos ntp para que sincronice la hora con time.hlg.sld.cu${DEFAULT}"
echo e "${AMARILLO}Editar el fichero de configuración, no sin antes hacerle una salva:${DEFAULT}"
cp /etc/systemd/timesyncd.conf{,.orig}
sed -i -r 's/#?(NTP)=.*$/\1=time\.hlg\.sld\.cu/' /etc/systemd/timesyncd.conf




#######################################################################################################################
###                                                                                                                 ###
###                                                                                                                 ###
###                            Haciendo una copia de seguridad de la configuración                                  ###
###                                                                                                                 ###
###                                                                                                                 ###
#######################################################################################################################
echo -e "${AMARILLO}Haciendo una copia de seguridad de la configuración de /etc${DEFAULT}"

## /etc/ldap/ldap.conf
if [ ! -f /etc/ldap/ldap.conf.ORIGINAL ]; then cp -p /etc/ldap/ldap.conf{,.ORIGINAL}; fi
verificar_error "cp -p /etc/ldap/ldap.conf{,.ORIGINAL}"

## Configuracion PAM common-account
if [ ! -f /etc/pam.d/common-account.ORIGINAL ]; then cp -p /etc/pam.d/common-account{,.ORIGINAL}; fi
verificar_error "cp -p /etc/pam.d/common-account{,.ORIGINAL}"

## Configuracion PAM common-auth
if [ ! -f /etc/pam.d/common-auth.ORIGINAL ]; then cp -p /etc/pam.d/common-auth{,.ORIGINAL}; fi
verificar_error "cp -p /etc/pam.d/common-auth{,.ORIGINAL}"

## Configuracion PAM common-password
if [ ! -f /etc/pam.d/common-password.ORIGINAL ]; then cp -p /etc/pam.d/common-password{,.ORIGINAL}; fi
verificar_error "cp -p /etc/pam.d/common-password{,.ORIGINAL}"

## Configuracion PAM common-session
if [ ! -f /etc/pam.d/common-session.ORIGINAL ]; then cp -p /etc/pam.d/common-session{,.ORIGINAL}; fi
verificar_error "cp -p /etc/pam.d/common-session{,.ORIGINAL}"

## Configuracion LDAP ldap.conf
if [ -f /etc/ldap.conf ]; then cp -pn /etc/ldap.conf{,.ORIGINAL}; fi
verificar_error "cp -pn /etc/ldap.conf{,.ORIGINAL}"

## Configuracion LDAP secret
if [ -f /etc/ldap.secret ]; then cp -pn /etc/ldap.secret{,.ORIGINAL}; fi
verificar_error "cp -pn /etc/ldap.secret{,.ORIGINAL}"

## Configuracion nslcd
if [ ! -f /etc/nslcd.conf.ORIGINAL ]; then cp -pn /etc/nslcd.conf{,.ORIGINAL}; fi
verificar_error "cp -pn /etc/nslcd.conf{,.ORIGINAL}"

## Configuracion nsswitch
if [ ! -f /etc/nsswitch.conf.ORIGINAL ]; then cp -pn /etc/nsswitch.conf{,.ORIGINAL}; fi
verificar_error "cp -pn /etc/nsswitch.conf{,.ORIGINAL}"


#######################################################################################################################
###                                                                                                                 ###
###                                                                                                                 ###
###                    Copiar los archivos modificados a sus lugares correspondientes                               ###
###                                                                                                                 ###
###                                                                                                                 ###
#######################################################################################################################
echo -e "${AMARILLO}Copiando los archivos modificados a sus lugares correspondientes${DEFAULT}"
## /etc/ldap/ldap.conf
echo -e "${etc_ldap_ldap_conf}" > /etc/ldap/ldap.conf
verificar_error "echo -e '${etc_ldap_ldap_conf}' > /etc/ldap/ldap.conf"

## Crear directorio
mkdir -p /etc/ldap/ssl

## /etc/ldap/ssl/server.pem
echo -e "${etc_ldap_ssl_server_pem}" > /etc/ldap/ssl/server.pem
verificar_error "echo -e '${etc_ldap_ssl_server_pem}' > /etc/ldap/ssl/server.pem"

## Configuracion PAM common-account
echo -e "${etc_pam_d_common_account}" > /etc/pam.d/common-account
verificar_error "echo -e '${etc_pam_d_common_account}' > /etc/pam.d/common-account"

## Configuracion PAM common-auth
echo -e "${etc_pam_d_common_auth}" > /etc/pam.d/common-auth
verificar_error "echo -e '${etc_pam_d_common_auth}' > /etc/pam.d/common-auth"

## Configuracion PAM common-password
echo -e "${etc_pam_d_common_password}" > /etc/pam.d/common-password
verificar_error "echo -e '${etc_pam_d_common_password}' > /etc/pam.d/common-password"

## Configuracion PAM common-session
echo -e "${etc_pam_d_common_sessiont}" > /etc/pam.d/common-session
verificar_error "echo -e '${etc_pam_d_common_session}' > /etc/pam.d/common-session"

## Configuracion LDAP ldap.conf
echo -e "${etc_ldap_conf}" > /etc/ldap.conf
verificar_error "echo -e '${etc_ldap_conf}' > /etc/ldap.conf"

## Configuracion LDAP secret
echo -e "${etc_ldap_secret}" > /etc/ldap.secret
verificar_error "echo -e '${etc_ldap_secret}' > /etc/ldap.secret"

## Configuracion nslcd
echo -e "${etc_nslcd_conf}" > /etc/nslcd.conf
verificar_error "echo -e '${etc_nslcd_conf}' > /etc/nslcd.conf"

## Configuracion nsswitch
echo -e "${etc_nsswitch_conf}" > /etc/nsswitch.conf
verificar_error "echo -e '${etc_nsswitch_conf}' > /etc/nsswitch.conf"



# Función para verificar si hubo algún error
function verificar_error {
    if [ $? -ne 0 ]; then
        echo -e "${ROJO}Hubo un error al ejecutar el comando: $1${DEFAULT}"
    fi
}

# Reiniciar los servicios necesarios
echo -e "${AMARILLO}Reiniciando los servicios necesarios${DEFAULT}"
systemctl restart nscd
verificar_error "systemctl restart nscd"
systemctl restart lightdm
verificar_error "systemctl restart lightdm"

# Notificar al usuario que la ejecución continúa
echo -e "${VERDE}Los servicios han sido reiniciados.${DEFAULT}"


#######################################################################################################################
###                                                                                                                 ###
###                                                                                                                 ###
###                             Agregando fuente de Windows para las Tipografias                                     ###
###                                                                                                                 ###
###                                                                                                                 ###
#######################################################################################################################
echo -e "${AMARILLO}Instalamos las fuentes de windows${DEFAULT}"
wget http://ftp.hlg.sld.cu/Linux/windows%20fonts.tar.gz
tar -xf windows\ fonts.tar.gz -C /usr/share/fonts/truetype

echo -e "${AMARILLO} Actualizamos las fuentes${DEFAULT}"
sleep 3s
fc-cache -f



#######################################################################################################################
###                                                                                                                 ###
###                                                                                                                 ###
###                                Detectando particiones y montando las mismas                                    ###
###                                                                                                                 ###
###                                                                                                                 ###
#######################################################################################################################
echo -e "${AMARILLO}Detectando particiones y montando las mismas${DEFAULT}"

# Verificar si ntfs-3g está instalado, y si no, instalarlo silenciosamente
if ! dpkg -s ntfs-3g >/dev/null 2>&1; then
    apt-get install -y -qq ntfs-3g
fi

# Obtener información de las particiones NTFS detectadas
disks=$(fdisk -l | grep -E "HPFS/NTFS" | awk '{print $1}')

# Mostrar las particiones detectadas
echo "${AMARILLO}Particiones NTFS detectadas:${DEFAULT}"
echo $disks

# Agregar un comentario para las particiones a montar en el archivo fstab
echo " " >> /etc/fstab
echo "## Particiones detectadas para montar automáticamente en el arranque" >> /etc/fstab


# Contador para la creación de carpetas
i=1

# Recorrer las particiones NTFS y obtener la ruta de dispositivo
for disk in $disks; do
    dev_path="$disk"
    
    # Crear carpeta para montar la partición
    carpetaMontar="/media/Datos$i"
    mkdir -p $carpetaMontar
    
    # Agregar la información al archivo fstab para montar automáticamente en el arranque
    echo "$dev_path $carpetaMontar ntfs-3g auto,rw,users,umask=000 0 0" >> /etc/fstab

    # Montar la partición
    mount -a
    
    # Mostrar mensaje de que la partición ha sido montada
    echo "${AMARILLO}  La partición $dev_path ha sido montada en $carpetaMontar  ${DEFAULT}"
    
    # Incrementar el contador
    i=$((i+1))
done

#######################################################################################################################
###                                                                                                                 ###
###                                                                                                                 ###
###                    Buscando navegadores en el sistema para instalar Mozilla Firefox                              ###
###                                                                                                                 ###
###                                                                                                                 ###
#######################################################################################################################
echo -e "${AMARILLO}Buscando navegadores en el sistema para instalar Mozilla Firefox ${DEFAULT}"

# Verificar si el usuario tiene permisos de root
if [[ $EUID -ne 0 ]]; then
   echo -e "${red}Este script debe ser ejecutado con permisos de root.${NC}"
   exit 1
fi

# Verificar si Mozilla Firefox está instalado
if which firefox >/dev/null; then
    native_version=$(firefox --version | awk '{print $3}')
    echo -e "${yellow}Se ha detectado una versión nativa de Mozilla Firefox ($native_version).${NC}"
    read -p "¿Desea eliminarla antes de instalar la versión más reciente? (s/n): " delete_native

    if [ "$delete_native" == "s" ]; then
        # Eliminar la versión nativa de Firefox
        apt-get remove -y firefox
        echo -e "${green}La versión nativa de Mozilla Firefox ha sido eliminada.${NC}"
    else
        echo -e "${green}La versión nativa de Mozilla Firefox se mantendrá.${NC}"
    fi
fi

# Verificar si hay otro navegador web instalado
if which google-chrome >/dev/null; then
    echo -e "${yellow}Se ha detectado que Google Chrome está instalado en el sistema.${NC}"
    read -p "¿Desea eliminarlo antes de instalar la versión más reciente de Mozilla Firefox? (s/n): " delete_chrome

    if [ "$delete_chrome" == "s" ]; then
        echo -e "${yellow}Eliminando Google Chrome...${NC}"
        # Eliminar Google Chrome
        apt-get remove -y google-chrome-stable
        echo -e "${green}Google Chrome ha sido eliminado.${NC}"
    else
        echo -e "${green}Google Chrome se mantendrá.${NC}"
    fi
fi

if which chromium-browser >/dev/null; then
    echo -e "${yellow}Se ha detectado que Chromium está instalado en el sistema.${NC}"
    read -p "¿Desea eliminarlo antes de instalar la versión más reciente de Mozilla Firefox? (s/n): " delete_chromium

    if [ "$delete_chromium" == "s" ]; then
        echo -e "${yellow}Eliminando Chromium...${NC}"
        # Eliminar Chromium
        apt-get remove -y chromium-browser
        echo -e "${green}Chromium ha sido eliminado.${NC}"
    else
        echo -e "${green}Chromium se mantendrá.${NC}"
    fi
fi

# Preguntar al usuario si quiere instalar Mozilla Firefox
read -p "¿Desea instalar Mozilla Firefox? (s/n): " install_firefox

if [ "$install_firefox" == "s" ]; then
    # Descargar el archivo desde la URL proporcionada
    wget http://ftp.hlg.sld.cu/Navegadores/Firefox/Linux/firefox-111.0.tar.bz2 -P /tmp/

    # Verificar la integridad del archivo descargado
    if ! bzip2 -tvv /tmp/firefox-111.0.tar.bz2 > /dev/null 2>&1; then
        echo -e "${red}El archivo firefox-111.0.tar.bz2 está dañado o incompleto.${NC}"
        exit 1
    fi

    # Descomprimir el archivo descargado
    tar -xjf /tmp/firefox-111.0.tar.bz2

    # Mover la carpeta de Firefox a /opt
    mv firefox /opt/

    # Crear un enlace simbólico para el lanzamiento de Firefox
    ln -s /opt/firefox/firefox /usr/bin/firefox

    # Crear un archivo firefox.desktop para lanzar Firefox
    echo -e "[Desktop Entry]
    Name=Firefox
    GenericName=Web Browser
    Comment=Access the Internet
    Exec=/opt/firefox/firefox %u
    Terminal=false
    X-MultipleArgs=false
    Type=Application
    Icon=/opt/firefox/browser/chrome/icons/default/default128.png
    Categories=Network;WebBrowser;
    MimeType=text/html;text/xml;application/xhtml+xml;application/xml;application/vnd.mozilla.xul+xml;application/rss+xml;application/rdf+xml;image/gif;image/jpeg;image/png;
    StartupNotify=true" > /usr/share/applications/firefox.desktop
# Agregar el archivo firefox.desktop al escritorio de todos los usuarios
    for user in /home/*
    do
        if [ -d "$user/Desktop" ]; then
            cp /usr/share/applications/firefox.desktop "$user/Desktop/"
            chown $(echo $user | cut -d'/' -f3):$(echo $user | cut -d'/' -f3) "$user/Desktop/firefox.desktop"
        fi
    done

    cp /usr/share/applications/firefox.desktop /usr/share/applications/internet/
    chown root:root /usr/share/applications/internet/firefox.desktop

    echo -e "${green}La instalación de Mozilla Firefox ha finalizado.${NC}"
else
    echo -e "${green}La instalación de Mozilla Firefox ha sido cancelada por el usuario.${NC}"
fi


##  Mostrar mensaje de finalización
echo -e "${VERDE}¡Gracias por usar nuestro script de instalación! Esperamos que te sea de gran utilidad. Recuerda que es importante reiniciar tu computadora para que los cambios tengan efecto.\nPor favor, reinicia tu PC para completar la instalación. ¡Hasta pronto!${DEFAULT}"

# Se muestra un mensaje para confirmar si se desea reiniciar la PC
read -p "¿Deseas reiniciar tu PC? (S/N): " respuesta

# Se verifica si la respuesta es "s" o "S"
if [[ "$respuesta" == "s" || "$respuesta" == "S" ]]; then
  echo "Reiniciando tu PC..."
  # Se utiliza el comando "sudo reboot" para reiniciar la PC
  sudo reboot
else
  echo "No se reiniciará tu PC."
fi


