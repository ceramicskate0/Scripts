#!/bin/bash
#-[Privilege Check Section]-
if [ $(id -u) -ne '0' ]; then
   echo
    echo ' [ERROR]: This Setup Script Requires root privileges!'
   echo '          Please run this setup script again with sudo or run as login as root.'
   echo
   exit 1
fi

func_getDependencies(){
  read -r -p "Run update and upgrade?[y/n]" response
  case "$response" in
  [yY][eE][sS]|[yY])
  apt-get updates && apt-get upgrade -y && apt-get dist-upgrade -y
  ;;
  esac
  echo 'Installing python'
  #install python
  if ! [ $(which python) ]; then
  apt-get install python python-pip git build-essential
  fi
  echo 'Installing Firewall'
  #install FW
  if ! [ $(which ufw) ]; then
  apt-get install ufw
  fi
  echo 'Installing linux sec auditing'
  #install baseline auditing
  if ! [ $(which lynis) ]; then
  apt-get install lynis
  fi
  echo 'Installing ClamAV'
  #install AV
  if ! [ $(which clamav) ]; then
  apt-get install clamav
  apt-get install clamav-freshclam
  fi
  echo 'Installing unattended-upgrades'
  #install auto upgrade software
  if ! [ $(which unattended-upgrades) ]; then
  apt-get install unattended-upgrades
  fi
}

func_Add_SocatRule(){
  #REF:https://www.pentestpartners.com/security-blog/socat-fu-lesson/
  if ! [ $(which socat) ]; then
  apt-get install socat
  fi
  echo "Enter Listening Port on Redir:"
  read RedirPort
  echo "Enter Long haul C2 Server Location:"
  read LongHaulC2
  echo "Enter Long haul C2 Server Listener Port:"
  read LongHaulC2_DestPort
  socat -v tcp4-listen:$RedirPort,reuseaddr,fork tcp4:$LongHaulC2:$LongHaulC2_DestPort
}

func_SSH_SetupKeyExchange(){
 if ! [ $(which ssh) ]; then
  apt-get install ssh
 fi
  echo 'Backup up current ssh config to /etc/ssh/backup.sshd_config'
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config_backup
  echo "Enter Username for ssh auth:"
  read NEWUSER
  echo "Enter remote machine ip or name:"
  read RemoteMachine
  runuser -l $NEWUSER -c ssh-keygen
  #ssh-keygen -t rsa -b 4096
  #Commented below is for manual key copy.
  runuser -l $NEWUSER ssh-copy-id $NEWUSER@$RemoteMachine
  #scp ~/.ssh/id_rsa.pub $NEWUSER@$NEWpassword:/home/$NEWUSER/.ssh/$NEWUSER.pub
  #mkdir -p /home/$NEWUSER/.ssh
  #cp /root/.ssh/authorized_keys /home/$NEWUSER/.ssh/authorized_keys
  #chown -R $NEWUSER:$NEWUSER /home/$NEWUSER
  #chmod 700 /home/$NEWUSER/.ssh
  #chmod 644 /home/$NEWUSER/.ssh/authorized_keys
  func_ModuliRegen
  service ssh restart
  ssh-add
}

func_install_forticlient(){
#REF:https://forticlient.com/repoinfo/etc/apt/source.list
 wget -O - https://repo.fortinet.com/repo/ubuntu/DEB-GPG-KEY | sudo apt-key add - 
 deb [arch=amd64] https://repo.fortinet.com/repo/ubuntu/ /bionic multiverse >> /etc/apt/sources.list
 #deb [arch=amd64] https://repo.fortinet.com/repo/ubuntu/ xenial multiverse >> /etc/apt/sources.list
 apt-get update 
 apt install forticlient 
}

func_setupSSH(){
  #install ssh  
  #https://medium.com/@jasonrigden/hardening-ssh-1bcb99cd4cef
 if ! [ $(which openssh-server) ]; then
  apt-get install openssh-server
 fi
  echo 'Backup up current ssh config to /etc/ssh/sshd_config_backup'
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config_backup
  read -r -p "Do you want to rewrite /etc/ssh/sshd_config?[y/n]" response
  case "$response" in
    [yY][eE][sS]|[yY])
    func_Write_SSHD_CONF
    ;;
    esac 
  echo 'Testing sshd config'
  sshd -t
  func_ModuliRegen
  service ssh restart
  systemctl reload sshd
}

func_ModuliRegen(){
  #REF:https://medium.com/@jasonrigden/hardening-ssh-1bcb99cd4cef
  echo 'Generating a new file may harden your server. Generating these file might take awhile.'
  read -r -p "Regen Moduli /etc/ssh/moduli file, if unsure say input n?[y/n]" response
  case "$response" in
    [yY][eE][sS]|[yY])
      ssh-keygen -G moduli-2048.candidates -b 2048
      ssh-keygen -T moduli-2048 -f moduli-2048.candidates
      cp moduli-2048 /etc/ssh/moduli
      rm moduli-2048
    ;;
    esac 
}

func_SSHD_CONF_2FA(){
  echo '#	$OpenBSD: sshd_config,v 1.101 2017/03/14 07:19:07 djm Exp $

  # This is the sshd server system-wide configuration file.  See
  # sshd_config(5) for more information.

  # This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

  # The strategy used for options in the default sshd_config shipped with
  # OpenSSH is to specify options with their default value where
  # possible, but leave them commented.  Uncommented options override the
  # default value.

  Port 22
  #AddressFamily any
  #ListenAddress 0.0.0.0
  #ListenAddress ::

  #HostKey /etc/ssh/ssh_host_rsa_key
  #HostKey /etc/ssh/ssh_host_ecdsa_key
  #HostKey /etc/ssh/ssh_host_ed25519_key

  # Ciphers and keying
  #RekeyLimit default none

  # Logging
  SyslogFacility AUTH
  LogLevel INFO

  # Authentication:

  #LoginGraceTime 2m
  PermitRootLogin no
  #StrictModes yes
  #MaxAuthTries 6
  #MaxSessions 10

  #PubkeyAuthentication yes

  # Expect .ssh/authorized_keys2 to be disregarded by default in future.
  #AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2

  #AuthorizedPrincipalsFile none

  #AuthorizedKeysCommand none
  #AuthorizedKeysCommandUser nobody

  # For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
  #HostbasedAuthentication no
  # Change to yes if you dont trust ~/.ssh/known_hosts for
  # HostbasedAuthentication
  #IgnoreUserKnownHosts no
  # Dont read the users ~/.rhosts and ~/.shosts files
  #IgnoreRhosts yes

  # To disable tunneled clear text passwords, change to no here!
  PasswordAuthentication no
  PermitEmptyPasswords no

  # Change to yes to enable challenge-response passwords (beware issues with
  # some PAM modules and threads)

  ChallengeResponseAuthentication yes

  # Kerberos options
  #KerberosAuthentication no
  #KerberosOrLocalPasswd yes
  #KerberosTicketCleanup yes
  #KerberosGetAFSToken no

  # GSSAPI options
  #GSSAPIAuthentication no
  #GSSAPICleanupCredentials yes
  #GSSAPIStrictAcceptorCheck yes
  #GSSAPIKeyExchange no

  # Set this to yes to enable PAM authentication, account processing,
  # and session processing. If this is enabled, PAM authentication will
  # be allowed through the ChallengeResponseAuthentication and
  # PasswordAuthentication.  Depending on your PAM configuration,
  # PAM authentication via ChallengeResponseAuthentication may bypass
  # the setting of "PermitRootLogin without-password".
  # If you just want the PAM account and session checks to run without
  # PAM authentication, then enable this but set PasswordAuthentication
  # and ChallengeResponseAuthentication to no.

  UsePAM yes
  AuthenticationMethods publickey,password publickey,keyboard-interactive

  #AllowAgentForwarding yes
  #AllowTcpForwarding yes
  #GatewayPorts no
  X11Forwarding yes
  #X11DisplayOffset 10
  #X11UseLocalhost yes
  #PermitTTY yes
  PrintMotd no
  PrintLastLog yes
  #TCPKeepAlive yes
  #UseLogin no
  #PermitUserEnvironment no
  #Compression delayed
  #ClientAliveInterval 0
  #ClientAliveCountMax 3
  #UseDNS no
  #PidFile /var/run/sshd.pid
  #MaxStartups 10:30:100
  #PermitTunnel no
  #ChrootDirectory none
  #VersionAddendum none

  # no default banner path
  #Banner none

  # Allow client to pass locale environment variables
  AcceptEnv LANG LC_*

  # override default of no subsystems
  Subsystem	sftp	/usr/lib/openssh/sftp-server

  # Example of overriding settings on a per-user basis
  #Match User anoncvs
  #	X11Forwarding no
  #	AllowTcpForwarding no
  #	PermitTTY no
  #	ForceCommand cvs server
  '
}

func_SSHD_CONF(){
 echo '
  #$OpenBSD: sshd_config,v 1.101 2017/03/14 07:19:07 djm Exp $
  # This is the sshd server system-wide configuration file.  See
  # sshd_config(5) for more information.
  # This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin
  # The strategy used for options in the default sshd_config shipped with
  # OpenSSH is to specify options with their default value where
  # possible, but leave them commented.  Uncommented options override the
  # default value.

  Port 22
  Protocol 2
  #AddressFamily any
  ListenAddress 0.0.0.0
  #ListenAddress ::

  HostKey /etc/ssh/ssh_host_rsa_key
  HostKey /etc/ssh/ssh_host_ecdsa_key
  HostKey /etc/ssh/ssh_host_ed25519_key

  # Ciphers and keying
  #RekeyLimit default none

  # Logging
  SyslogFacility AUTH
  LogLevel INFO

  # Authentication:
  #PubkeyAuthentication yes
  # To disable tunneled clear text passwords, change to no here!
  PasswordAuthentication yes
  PermitEmptyPasswords no

  # Set this to yes to enable PAM authentication, account processing,
  # and session processing. If this is enabled, PAM authentication will
  # be allowed through the ChallengeResponseAuthentication and
  # PasswordAuthentication.  Depending on your PAM configuration,
  # PAM authentication via ChallengeResponseAuthentication may bypass
  # the setting of "PermitRootLogin without-password".
  # If you just want the PAM account and session checks to run without
  # PAM authentication, then enable this but set PasswordAuthentication
  # and ChallengeResponseAuthentication to no.
  UsePAM no

  #LoginGraceTime 2m
  PermitRootLogin no
  #StrictModes yes
  MaxAuthTries 6
  MaxSessions 2

  # Expect .ssh/authorized_keys2 to be disregarded by default in future.
  #AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2

  #AuthorizedPrincipalsFile none

  #AuthorizedKeysCommand none
  #AuthorizedKeysCommandUser nobody

  # For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
  #HostbasedAuthentication no
  # Change to yes if you dont trust ~/.ssh/known_hosts for
  # HostbasedAuthentication
  #IgnoreUserKnownHosts no
  # Dont read the users ~/.rhosts and ~/.shosts files
  #IgnoreRhosts yes

  # Change to yes to enable challenge-response passwords (beware issues with
  # some PAM modules and threads)
  ChallengeResponseAuthentication no

  # Kerberos options
  #KerberosAuthentication no
  #KerberosOrLocalPasswd yes
  #KerberosTicketCleanup yes
  #KerberosGetAFSToken no

  # GSSAPI options
  #GSSAPIAuthentication no
  #GSSAPICleanupCredentials yes
  #GSSAPIStrictAcceptorCheck yes
  #GSSAPIKeyExchange no

  #AllowAgentForwarding yes
  #AllowTcpForwarding yes
  #GatewayPorts no
  X11Forwarding no
  #X11DisplayOffset 10
  #X11UseLocalhost yes
  #PermitTTY yes
  PrintMotd yes
  PrintLastLog yes
  #TCPKeepAlive yes
  #UseLogin no
  #PermitUserEnvironment no
  #Compression delayed
  ClientAliveInterval 300
  ClientAliveCountMax 2
  #UseDNS no
  #PidFile /var/run/sshd.pid
  #MaxStartups 10:30:100
  #PermitTunnel no
  #ChrootDirectory none
  #VersionAddendum none

  # no default banner path
  #Banner none

  # Allow client to pass locale environment variables
  AcceptEnv LANG LC_*

  # override default of no subsystems
  Subsystem	sftp	/usr/lib/openssh/sftp-server

  # Example of overriding settings on a per-user basis
  #Match User anoncvs
  #	X11Forwarding no
    #	AllowTcpForwarding no
  #	PermitTTY no
  #	ForceCommand cvs server
    '
}

func_SSH_PAMD_CONF_2FA(){
  echo '# PAM configuration for the Secure Shell service

  # Standard Un*x authentication.
  #@include common-auth

  # Disallow non-root logins when /etc/nologin exists.
  account    required     pam_nologin.so

  # Uncomment and edit /etc/security/access.conf if you need to set complex
  # access limits that are hard to express in sshd_config.
  # account  required     pam_access.so

  # Standard Un*x authorization.
  @include common-account

  # SELinux needs to be the first session rule.  This ensures that any
  # lingering context has been cleared.  Without this it is possible that a
  # module could execute code in the wrong domain.
  session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close

  # Set the loginuid process attribute.
  session    required     pam_loginuid.so

  # Create a new session keyring.
  session    optional     pam_keyinit.so force revoke

  # Standard Un*x session setup and teardown.
  @include common-session

  # Print the message of the day upon successful login.
  # This includes a dynamically generated part from /run/motd.dynamic
  # and a static (admin-editable) part from /etc/motd.
  session    optional     pam_motd.so  motd=/run/motd.dynamic
  session    optional     pam_motd.so noupdate

  # Print the status of the users mailbox upon successful login.
  session    optional     pam_mail.so standard noenv # [1]

  # Set up user limits from /etc/security/limits.conf.
  session    required     pam_limits.so

  # Read environment variables from /etc/environment and
  # /etc/security/pam_env.conf.
  session    required     pam_env.so # [1]
  # In Debian 4.0 (etch), locale-related environment variables were moved to
  # /etc/default/locale, so read that as well.
  session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale

  # SELinux needs to intervene at login time to ensure that the process starts
  # in the proper default security context.  Only sessions which are intended
  # to run in the users context should be run after this.
  session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open

  # Standard Un*x password updating.
  @include common-password
  auth required pam_google_authenticator.so'
}

func_Write_SSHD_CONF(){
 echo ''
 echo '------------------------------------------'
 echo '              sshd_conf'
 echo ''------------------------------------------''
 echo ''
 func_SSHD_CONF
 func_SSHD_CONF > /etc/ssh/sshd_config
 echo ''
 echo '------------------------------------------'
 echo '              sshd_conf'
 echo ''------------------------------------------''
 read -r -p "Do you want to turn off ssh password and only allow keyexchange?[y/n]" response
 case "$response" in
 [yY][eE][sS]|[yY])
 sed -i -e 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
 ;;
 esac 
 service ssh restart
 systemctl reload sshd
 echo ''
}

func_SecAudit(){
  if ! [ $(which lynis) ]; then
  apt-get install lynis
  fi
  lynis audit system
}

func_createUser(){
    echo "Enter New UserName:"
    read NEWUSER
    adduser $NEWUSER
    usermod -aG sudo $NEWUSER
}

func_setupFail2Ban(){
    #REF:https://medium.com/@jasonrigden/hardening-ssh-1bcb99cd4cef
   if ! [ $(which fail2ban) ]; then
   apt-get install fail2ban
   fi
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    echo '!!!COPY BELOW NOW!!!!'
    echo 'Open the /etc/fail2ban/jail. Local files and find the spot that starts.
    Edit it like so, 
    Add the enable=true to the [sshd] section so it looks like this around line 244,
    [sshd]
    #mode   = normal 
    port    = ssh
    logpath = %(sshd_log)s
    backend = %(sshd_backend)s
    enable=true '| cat
    echo '!!! Above is used to update config that will be opened next.!!!! '
    echo 'Also Add the enable=true line to any service you want to use fail2ban on.'
    read -p "Press enter to continue"
    if ! [ $(which nano) ]; then
    apt-get install nano
    fi
    nano /etc/fail2ban/jail.local
    service fail2ban restart
}

func_setup2FA(){
    #REF:https://medium.com/@jasonrigden/hardening-ssh-1bcb99cd4cef
    #REF:https://www.digitalocean.com/community/tutorials/how-to-set-up-multi-factor-authentication-for-ssh-on-ubuntu-14-04
      if ! [ $(which openssh-server) ]; then
        if ! [ $(which libpam-google-authenticator) ]; then
            apt-get install libpam-google-authenticator
        fi
      echo 'Enter username for 2FA:'
      read Username
      if [ -e /home/$Username/.google_authenticator ]
       then
        echo '2FA found to exist for user. No need for setup. 
        To force setup run google-authenticator command as that user.'
        read -r -p "Redo setup for user $Username ?[y/n]" response
        case "$response" in
        [yY][eE][sS]|[yY])
        runuser -l $Username -c google-authenticator
        func_SSH_PAMD_CONF_2FA>/etc/pam.d/sshd
        func_SSHD_CONF_2FA > /etc/ssh/sshd_config
        service ssh restart
        ;;
        esac 
      else
        runuser -l $Username -c google-authenticator
        func_SSH_PAMD_CONF_2FA>/etc/pam.d/sshd
        func_SSHD_CONF_2FA > /etc/ssh/sshd_config
        service ssh restart
      fi
      else 
        echo 'Openssh server not installed please run option to insta;;/harden ssh first.'
      fi
}

func_setupFileBeat(){
   #REF:https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elastic-stack-on-ubuntu-18-04#step-4-%E2%80%94-installing-and-configuring-filebeat
   if ![ $(which filebeat) ]; then
   wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
   echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
   apt-get update
   apt install filebeat
   fi
   echo "Enter log Forwarder location (where to send logs to):"
   read $LogForwarder
   echo "Enter log Forwarder port (port to send logs to):"
   read $LogForwarderPort
   sed -i -e 's/hosts: ["localhost:9200"]/hosts: ["'$LogForwarder':'$LogForwarderPort'"] /g' /etc/filebeat/filebeat.yml
   echo "Enter log Forwarder username for https:"
   read $username
   sed -i -e 's/#username: "elastic"/username: "'$username'"/g' /etc/filebeat/filebeat.yml
   echo "Enter log Forwarder password for https:"
   read $password
   sed -i -e 's/#password: "changeme"/password: "'$password'"/g' /etc/filebeat/filebeat.yml
   sed -i -e 's/#logging.level: debug/logging.level: warning/g' /etc/filebeat/filebeat.yml
   filebeat modules enable system
   filebeat modules list
   filebeat setup --template -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["localhost:9200"]'
   systemctl start filebeat
   systemctl enable filebeat
}

func_setupRsyslog(){
   #REF:https://www.digitalocean.com/community/tutorials/how-to-centralize-logs-with-rsyslog-logstash-and-elasticsearch-on-ubuntu-14-04
   if ![ $(which rsyslog) ]; then
   apt-get install rsyslog
   fi
   echo "Enter log Forwarder location (where to send logs to):"
   read $LogForwarder
   echo "Enter log Forwarder port (port to send logs to):"
   read $LogForwarderPort
   sed -i -e 's/#$ModLoad imudp/$ModLoad imudp/g'/etc/rsyslog.conf
   sed -i -e 's/#$UDPServerRun 514/$UDPServerRun '$LogForwarderPort'/g' /etc/rsyslog.conf
   sed -i -e 's/@private_ip_of_ryslog_server:514/'$LogForwarder':'$LogForwarderPort'/g' /etc/rsyslog.d/50-default.conf
   service rsyslog restart
}

func_build_pkcs(){
  cd /etc/letsencrypt/live/$domain
  echo '[Starting] Building PKCS12 .p12 cert.'
  openssl pkcs12 -export -in fullchain.pem -inkey privkey.pem -out $domainPkcs -name $domain -passout pass:$password
  echo '[Success] Built $domainPkcs PKCS12 cert.'
  echo '[Starting] Building Java keystore via keytool.'
  keytool -importkeystore -deststorepass $password -destkeypass $password -destkeystore $domainStore -srckeystore $domainPkcs -srcstoretype PKCS12 -srcstorepass $password -alias $domain
  echo '[Success] Java keystore $domainStore built.'
  mkdir $cobaltStrikeProfilePath
  cp $domainStore $cobaltStrikeProfilePath
  echo '[Success] Moved Java keystore to CS profile Folder.'
}

func_install_letsencrypt(){
  echo -n "Enter your DNS (A) record for domain [ENTER]: "
  read domain
  echo '' 
  echo -n "Enter your common password to be used [ENTER]: "
  read password
  echo '' 
  domainPkcs="$domain.p12"
  domainStore="$domain.store"
  echo '[Starting] cloning into /opt/letsencrypt!'
  git clone https://github.com/certbot/certbot /opt/letsencrypt
  echo '[Starting] to build letsencrypt cert!'
  if [ -f /opt/letsencryptletsencrypt-auto]; then
    ./opt/letsencryptletsencrypt-auto --apache -d $domain -n --register-unsafely-without-email --agree-tos 
  if [ -e /etc/letsencrypt/live/$domain/fullchain.pem ]; then
    echo '[Success] letsencrypt certs are built!'
  else
    echo "[ERROR] letsencrypt certs failed to build.  Check that DNS A record is properly configured for this domain"
    exit 1
  fi
  cd /etc/letsencrypt/live/$domain
  echo '[Starting] Building PKCS12 .p12 cert.'
  openssl pkcs12 -export -in fullchain.pem -inkey privkey.pem -out $domainPkcs -name $domain -passout pass:$password
  echo '[Success] Built $domainPkcs PKCS12 cert.'
  echo '[Starting] Building Java keystore via keytool.'
  keytool -importkeystore -deststorepass $password -destkeypass $password -destkeystore $domainStore -srckeystore $domainPkcs -srcstoretype PKCS12 -srcstorepass $password -alias $domain
  echo '[Success] Java keystore $domainStore built.'
  mkdir $cobaltStrikeProfilePath
  cp $domainStore $cobaltStrikeProfilePath
  echo '[Success] Moved Java keystore to CS profile Folder.'
  func_build_pkcs

  else
   echo 'FAILED to clone https://github.com/certbot/certbot from github!!!'  
   fi
}

func_installDefensiveTools(){
  #REF:https://www.digitalocean.com/community/tutorials/how-to-install-and-use-logwatch-log-analyzer-and-reporter-on-a-vps
  BUILDDIR=$(pwd)
  apt-get update
  pip install lterm
  mkdir lterm_logs
  python /usr/local/bin/lterm.py -b -i -l $BUILDDIR/lterm_logs/
  apt-get install sendmail logwatch
  echo 'Enter Email to send alert too:'
  read EmailTo
  sed -i -e 's/MailTo = root/MailTo = '$EmailTo'/' /usr/share/logwatch/default.conf/logwatch.conf
  sed -i -e 's/Range = yesterday/Range = today/' /usr/share/logwatch/default.conf/logwatch.conf
  sed -i -e 's/Detail = Low/Detail = Med/' /usr/share/logwatch/default.conf/logwatch.conf
  (crontab -l 2>/dev/null; echo "0 * * * * /usr/sbin/logwatch --detail Med --mailto' $EmailTo' --service all --range today") | crontab -
  apt-get install iptables-persistent
}

func_SetupBaselineForFW(){
   if ![ $(which ufw) ]; then
    apt-get install ufw
    ufw disable
    ufw enable
    fi
    echo 'Enter the IP you want to be allowed to ssh to this box from (hit enter to skip):'
    read HOMEIP
    ufw enable
    ufw allow from $HOMEIP to any port 22
    ufw default deny incoming
    ufw default deny outgoing
    ufw status numbered
    while true
    do
    echo ""
    echo "-------------"
    echo "- Firewall Config Menu -"
    echo "-------------"
    echo ""
    echo "-------------"
    echo "- Firewall Rules-"
    echo "-------------"
    ufw status numbered
    echo ""
    echo ""
    echo ""
    echo "======================================================================"
    echo "[*] Select option to start setup for UFW Firewall on Local host[*]"
    echo "======================================================================"
    echo "Enter 1 to open port for inbound connection (incoming):"
    echo "Enter 2 to open port to outbound connection (outgoing):"
    echo "Enter 3 to add a rule to DROP Ping Requests(incoming):"
    echo "Enter 4 to allow IP incoming with dest Port (incoming):"
    echo "Enter 5 to allow to IP from this machine to an IP (outgoing):"
    echo "Enter 6 for Custom UFW (ie ufw+ your command in bash):"
    echo "Enter 7 to delete UFW FW by rule num:"
    echo "Enter 8 reset ufw (FW):"
    echo "Enter 99 to exit script"
    echo "Please enter your selection: "
    read answer
    case "$answer" in
    # -------------------------------------------------------------------------------------
    # -[User Selection Section]-
    1) echo 'Enter port to open from internet:'
      read port
      echo 'Enter udp or tcp for port type:'
      read TranmissionType
      ufw allow proto $TranmissionType from any to any port $port
      #ufw allow $port/$TranmissionType
      echo "[*] - COMPLETE!"
      ;;
    2) echo 'Enter port to open to internet:'
      read port
      echo 'Enter udp or tcp for port type:'
      read TranmissionType
      ufw allow out $port/$TranmissionType
      #ufw allow $port/$TranmissionType
      echo "[*] - COMPLETE!"
      ;;
    3) echo '-A ufw-before-input -p icmp --icmp-type echo-request -j DROP' >> '/etc/ufw/before.rules'
       echo "[*] - COMPLETE!"
       ;;
    4) echo 'Enter IP to open incoming from:'
      read IP
      echo 'Enter port to allow IP inbound to:'
      read port
      ufw allow from $IP to any port $port
      echo "[*] - COMPLETE!"
      ;;
    5) echo 'Enter IP to allow comms to:'
      read IP
      ufw allow to $IP
      echo "[*] - COMPLETE!"
      ;;
    6)  echo 'Enter custom UFW: UFW '
       read cmd
       ufw + ' '+$cmd
       echo "[*] - COMPLETE!"
       ;;
    7)  ufw status numbered 
       echo 'Enter rule number to remove: '
       read cmd
       ufw delete $cmd
       echo "[*] - COMPLETE!"
       ;;
    8) ufw reset
       echo "[*] - COMPLETE!"
       ;;
    99) clear
       echo "[*] - Exiting script..."
       func_Main
      ;;
    esac 
  done
}

func_Main(){
    echo ""
    echo "-------------"
    echo "- Main Menu -"
    echo "-------------"
    echo ""
    echo "======================================================================"
    echo "[*] Select option to start setup for redir[*]"
    echo "======================================================================"
    echo "Enter 0 Setup SSH Key Exchange on remote machine (run on Workstation not SERVER)"
    echo "Enter 1 Setup/Harden SSH (run on SERVER)"
    echo "Enter 2 Setup FW (run on SERVER)"
    echo "Enter 3 Add Users (run on SERVER)"
    echo "Enter 4 Add Socat Rule (run on SERVER)"
    echo "Enter 5 Sec Audit System (run on SERVER)"
    echo "Enter 6 Setup 2FA (run on SERVER)"
    echo "Enter 7 Setup Fail2ban(run on SERVER)"
    echo "Enter 8 Setup a Log Forwarder (run on SERVER)"
    echo "Enter 9 Setup LetsEncrypt (run on SERVER)"
    echo "Enter 10 Install Forticlient (run on Any)
    echo "Enter 99 to Exit Script"
    echo "Please enter your selection: "
    read answer
    case "$answer" in
 # -------------------------------------------------------------------------------------
    0) clear
      #https://medium.com/@jasonrigden/hardening-ssh-1bcb99cd4cef
      func_SSH_SetupKeyExchange
      echo "[*] - COMPLETE!"
      func_Main
      ;;
    1) clear
      #https://medium.com/@jasonrigden/hardening-ssh-1bcb99cd4cef
      func_setupSSH
      echo "[*] - COMPLETE!"
      func_Main
      ;;
    2) clear
      #REF:https://www.digitalocean.com/community/tutorials/how-to-setup-a-firewall-with-ufw-on-an-ubuntu-and-debian-cloud-server
      func_SetupBaselineForFW
      echo "[*] - COMPLETE!"
      func_Main
      ;;
    3) clear
      func_createUser
      echo "[*] - COMPLETE!"
      func_Main
      ;;
    4) clear
      func_Add_SocatRule
      echo "[*] - COMPLETE!"
      func_Main
      ;;
    5) clear
      func_SecAudit
      echo "[*] - COMPLETE!"
      func_Main
      ;;
    6) clear
      #https://medium.com/@jasonrigden/hardening-ssh-1bcb99cd4cef
      func_setup2FA
      echo "[*] - COMPLETE!"
      func_Main
      ;;
    7) clear
      #https://medium.com/@jasonrigden/hardening-ssh-1bcb99cd4cef
      func_setupFail2Ban
      echo "[*] - COMPLETE!"
      func_Main
      ;;
    8) clear
      read -r -p "Setup FileBeat?[y/n]" response
      case "$response" in
      [yY][eE][sS]|[yY])
      func_setupFileBeat
      ;;
      esac 
      read -r -p "Setup Rsyslog?[y/n]" response
      case "$response" in
      [yY][eE][sS]|[yY])
      func_setupRsyslog
      ;;
      esac
      read -r -p "Setup lterm log monitoring with email alerting?[y/n]" response
      case "$response" in
      [yY][eE][sS]|[yY])
      func_installDefensiveTools
      ;;
      esac
      echo "[*] - COMPLETE!"
      func_Main
      ;;
    9) clear
      func_install_letsencrypt
      echo "[*] - COMPLETE!"
      func_Main
      ;;
    10) clear
      func_install_forticlient
      echo "[*] - COMPLETE!"
      func_Main
      ;;
    99) clear
      echo "[*] - Exiting script"
      exit 0
      ;;
  esac
}
# -------------------------------------------------------------------------------------
func_getDependencies
func_Main
