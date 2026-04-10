from enum import Enum

class Protocol(str, Enum):
    SSH="SSH"; HTTP="HTTP"; HTTPS="HTTPS"; TELNET="TELNET"; FTP="FTP"; RDP="RDP"; SMB="SMB"; LDAP="LDAP"; DNS="DNS"; VNC="VNC"; MYSQL="MYSQL"; POSTGRESQL="POSTGRESQL"; REDIS="REDIS"; MONGODB="MONGODB"; ELASTICSEARCH="ELASTICSEARCH"; MSSQL="MSSQL"; K8S_API="K8S_API"; AWS_METADATA="AWS_METADATA"; SMTP="SMTP"; SNMP="SNMP"; SIP="SIP"; MEMCACHED="MEMCACHED"; DOCKER_API="DOCKER_API"
class Severity(str, Enum):
    INFO="info"; LOW="low"; MEDIUM="medium"; HIGH="high"; CRITICAL="critical"
class DecoyType(str, Enum):
    SSH_HONEYPOT="ssh_honeypot"; HTTP_HONEYPOT="http_honeypot"; HTTPS_HONEYPOT="https_honeypot"; TELNET_HONEYPOT="telnet_honeypot"; FTP_HONEYPOT="ftp_honeypot"; RDP_HONEYPOT="rdp_honeypot"; SMB_HONEYPOT="smb_honeypot"; LDAP_HONEYPOT="ldap_honeypot"; DNS_HONEYPOT="dns_honeypot"; VNC_HONEYPOT="vnc_honeypot"; MYSQL_HONEYPOT="mysql_honeypot"; POSTGRESQL_HONEYPOT="postgresql_honeypot"; REDIS_HONEYPOT="redis_honeypot"; MONGODB_HONEYPOT="mongodb_honeypot"; ELASTICSEARCH_HONEYPOT="elasticsearch_honeypot"; MSSQL_HONEYPOT="mssql_honeypot"; K8S_API_HONEYPOT="k8s_api_honeypot"; AWS_METADATA_HONEYPOT="aws_metadata_honeypot"; SMTP_HONEYPOT="smtp_honeypot"; SNMP_HONEYPOT="snmp_honeypot"; SIP_HONEYPOT="sip_honeypot"; MEMCACHED_HONEYPOT="memcached_honeypot"; DOCKER_API_HONEYPOT="docker_api_honeypot"
class AlertStatus(str, Enum):
    NEW="new"; INVESTIGATING="investigating"; RESOLVED="resolved"; SUPPRESSED="suppressed"
class DecoyStatus(str, Enum):
    DRAFT="draft"; DEPLOYING="deploying"; ACTIVE="active"; PAUSED="paused"; ERROR="error"; DESTROYED="destroyed"
