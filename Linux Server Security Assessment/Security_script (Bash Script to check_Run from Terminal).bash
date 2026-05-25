#!/bin/bash
# Linux Server Security Healthcheck
#
# OUTPUT FILES:
#
#   --- Healthcheck Results ---
#   HC_FirewallState.txt       HC_KernelHardening.txt   HC_MACEnforcement.txt
#   HC_RiskyServices.txt       HC_ListeningPorts.txt    HC_PatchStatus.txt
#
#   --- Integrity ---
#   Hashes.txt                 MetaData.txt
#
#   --- System Info ---
#   SystemInformation.txt      Journal.txt
#
#   --- Users, Groups & Rights ---
#   Userinformation.txt        Groupinformation.txt     NetgroupInformation.txt
#   Lastlogininformation.txt   Wtmpfilelastlogininformation.txt
#   Sudoers.txt                SudoersDirectory.txt
#
#   --- Passwords & PAM ---
#   Passwordinformation.txt    commonauth.txt           commonpassword.txt
#   system-auth.txt            password-auth.txt        loginpassword.txt
#   sshdPassword.txt           pamconfig.txt            passwordquality.txt
#   passwordqc.txt             faillockconfig.txt
#
#   --- SSH & Access Controls ---
#   Sshdconfig.txt             securetty.txt            login.txt
#   hostequiv.txt              rhosts.txt               accessconfig.txt
#
#   --- Services ---
#   riskyServices.txt          inetdConfig.txt
#
# Version of Linux Script
version='1.1'

# Helper: append stat metadata for a given file path to MetaData.txt
# Usage: metafile <filepath>
metafile() {
    local target="$1"
    if [ -e "$target" ]; then
        stat -c "%a;%n;%U;%G;%Z;%Y" "$target" >> MetaData.txt
    fi
}

echo 'Starting Script..'

############################
# Initialization - Hashing #
############################

# Create file for hashing
echo 'Hash  Hashfile' > Hashes.txt

# Create MetaData file, showcasing modification dates of general underlying files used in this script
echo 'Permissions;FileName;Owner user name;Owner group name;Last status change;Last modification' > MetaData.txt

declare -a FilesToCheck=("/" "/bin" "/dev" "/etc" "/etc/*.d" "/etc/security" "/home" "/opt" "/sbin" "/usr" "/usr/bin"
"/usr/sbin/" "/usr/etc" "/usr/lib" "/usr/local" "/usr/local/bin" "/usr/local/sbin/" "/usr/local/lib" "/usr/spool"
"/var" "/var/log" "/var/www/" "/var/nis/" "/var/spool" "/var/spool/cron/crontabs" "/etc/passwd" "/etc/shadow" "/etc/rsyslog.d/*" 
"/etc/group" "/etc/ssh/sshd_config" "/etc/sudoers")

for file in "${FilesToCheck[@]}"; do
        stat -c "%a;%n;%U;%G;%Z;%Y" $file 2>/dev/null >> MetaData.txt
done

###########
# Logging #
###########

echo "Processing logging files."

# Get journal information for logging period & corresponding hash
if file /sbin/init | grep "systemd" &>/dev/null; then
    journalctl -n 1 > Journal.txt
else
    echo "No systemd detected. If relevant check with the client and inspect /etc/logrotate.conf and /etc/logrotate.d for logging settings." > Journal.txt
fi

sha1sum Journal.txt >> Hashes.txt  

############################
# Users, groups and rights #
############################

echo "Processing users, groups and related rights."

# Get last login of all users & corresponding hash
lastlog > Lastlogininformation.txt
sha1sum Lastlogininformation.txt >> Hashes.txt

last -Fwa -s '-24 month'| head -n -2 | awk -v pattern="reboot" -v pattern2="logged" -v pattern3="down" -v pattern4="crash" -v pattern5="logout" '$1 !~ pattern && $9 !~ pattern2 && $9 !~ pattern3 && $9 !~ pattern4 && $9 !~ pattern5 {print $1,$2,$15,$9,$10,$11,$12,$13}' > Wtmpfilelastlogininformation.txt
sha1sum Wtmpfilelastlogininformation.txt >> Hashes.txt

# User information & corresponding hash
cat /etc/passwd > Userinformation.txt
sha1sum Userinformation.txt >> Hashes.txt  
 
# Get group information & corresponding hash
cat /etc/group > Groupinformation.txt 
sha1sum Groupinformation.txt >> Hashes.txt  

# Get netgroup information corresponding hash
cat /etc/netgroup > NetgroupInformation.txt
sha1sum NetgroupInformation.txt >> Hashes.txt

# Get all user/group assigned rights & corresponding hash
cat /etc/sudoers > Sudoers.txt
sha1sum Sudoers.txt >> Hashes.txt  

# Check if the sudoers files contain a reference to the sudoers.d directory [ -d "/etc/sudoers.d" ].
# Due to legacy reasons these references can be done with #includedir or @include
# Parameter -xq mean that it has to match the whole line and doesn't write anything to output since it's just a check
# If the folder exists, append all files within the directory to the output.
if grep -xq '[#@]includedir /etc/sudoers.d' /etc/sudoers && [ -d "/etc/sudoers.d" ]; then 
    for File in /etc/sudoers.d/*; do cat "$File" >> SudoersDirectory.txt; done

    sha1sum SudoersDirectory.txt >> Hashes.txt
fi

############################ 
# Actual Password settings #
############################

echo "Processing password settings."

# Get password information of users. Set the 9th field to locked when passwords are locked and then print everything except the password hash itself
cat /etc/shadow | awk -F ':' -v OFS=':' '$1 { if ($2=="*"||$2=="!"||$2=="!!"||index($2,"!")==1) $9="Locked"; $10="No password set"; if ($2 ~ /^!*\$([56]|2a)\$/) $10="Secure"; if ($2 ~ /^!*\$1\$/) $10="Not secure"; print $1, $3, $4, $5, $6, $7, $8, $9, $10 }' > Passwordinformation.txt

# Create hash from file and add the hash to file containing all hashes
sha1sum Passwordinformation.txt >> Hashes.txt    

#########################################################
# Password settings information files, when they exist! #
#########################################################


# If the /etc/pam.d directory exists, the /etc/pam.conf is ignored in favor of the entries in the /etc/pam.d directory. Otherwise, pam.conf is the default.
if [ -d "/etc/pam.d" ]; then
    # common-auth
    commonauthfile=/etc/pam.d/common-auth
    if [ -f "$commonauthfile" ]; then
        cat "$commonauthfile" > commonauth.txt

        sha1sum commonauth.txt >> Hashes.txt
        stat -c "%a;%n;%U;%G;%Z;%Y" "$commonauthfile" >> MetaData.txt
    fi

    # common-password
    commonpwdfile=/etc/pam.d/common-password
    if [ -f "$commonpwdfile" ]; then
        cat "$commonpwdfile" > commonpassword.txt

        sha1sum commonpassword.txt >> Hashes.txt
        stat -c "%a;%n;%U;%G;%Z;%Y" "$commonpwdfile" >> MetaData.txt
    fi

    # system-auth
    systemauthfile=/etc/pam.d/system-auth
    if [ -f "$systemauthfile" ]; then
        cat "$systemauthfile" > system-auth.txt

        sha1sum system-auth.txt >> Hashes.txt      
        stat -c "%a;%n;%U;%G;%Z;%Y" "$systemauthfile" >> MetaData.txt
    fi

    # password-auth
    passwordauthfile=/etc/pam.d/password-auth
    if [ -f "$passwordauthfile" ]; then
        cat "$passwordauthfile" > password-auth.txt

        sha1sum password-auth.txt >> Hashes.txt      
        stat -c "%a;%n;%U;%G;%Z;%Y" "$passwordauthfile" >> MetaData.txt
    fi

    # PAM settings for the login service
    login=/etc/pam.d/login
    other=/etc/pam.d/other
    if [ -f "$login" ]; then
        cat "$login" > loginpassword.txt
  
        stat -c "%a;%n;%U;%G;%Z;%Y" "$login" >> MetaData.txt
    elif [ -f "$other" ]; then
        cat "$other" > loginpassword.txt
  
        stat -c "%a;%n;%U;%G;%Z;%Y" "$other" >> MetaData.txt
    else 
        echo "Neither pam.d/login nor pam.d/other were found." > loginpassword.txt
    fi

    sha1sum loginpassword.txt >> Hashes.txt

    # PAM settings for the sshd service
    sshd=/etc/pam.d/sshd
    if [ -f "$sshd" ]; then
        cat "$sshd" > sshdPassword.txt
  
        stat -c "%a;%n;%U;%G;%Z;%Y" "$sshd" >> MetaData.txt
    elif [ -f "$other" ]; then
        cat "$other" > sshdPassword.txt

        stat -c "%a;%n;%U;%G;%Z;%Y" "$other" >> MetaData.txt
    else 
        echo "Neither pam.d/sshd nor pam.d/other were found." > sshdPassword.txt
    fi

    sha1sum sshdPassword.txt >> Hashes.txt
else
    pamconfig=/etc/pam.conf
    cat "$pamconfig" > pamconfig.txt

    sha1sum pamconfig.txt >> Hashes.txt   
    stat -c "%a;%n;%U;%G;%Z;%Y" "$pamconfig" >> MetaData.txt
fi

# pwquality, used by the pam_pwquality and pam_cracklib modules
pwdquality=/etc/security/pwquality.conf
if [ -f "$pwdquality" ]; then
    cat "$pwdquality" > passwordquality.txt

    stat -c "%a;%n;%U;%G;%Z;%Y" "$pwdquality" >> MetaData.txt

    if [ -d "/etc/security/pwquality.conf.d" ]; then
        for File in /etc/security/pwquality.conf.d/*; do cat "$File" >> passwordquality.txt; done
    fi

    sha1sum passwordquality.txt >> Hashes.txt   
fi

# /etc/passwdqc.conf is used by the pam_passwdqc module as configuration file
passwdqc=/etc/passwdqc.conf
if [ -f "$passwdqc" ]; then
    cat "$passwdqc" > passwordqc.txt

    sha1sum passwordqc.txt >> Hashes.txt   
    stat -c "%a;%n;%U;%G;%Z;%Y" "$passwdqc" >> MetaData.txt
fi

##################
# FIREWALL STATE #
##################

echo "Processing firewall state."

{
    echo "=== Firewall State ==="
    echo "Checked: $(date +"%m-%d-%Y %H:%M:%S")"
    echo ""

    if command -v ufw &>/dev/null; then
        echo "--- UFW ---"
        ufw status verbose 2>/dev/null
    fi

    if command -v firewall-cmd &>/dev/null; then
        echo ""
        echo "--- firewalld ---"
        firewall-cmd --state 2>/dev/null
        firewall-cmd --list-all 2>/dev/null
    fi

    echo ""
    echo "--- iptables INPUT chain ---"
    iptables -L INPUT -n -v 2>/dev/null || echo "iptables not available."

    echo ""
    echo "--- ip6tables INPUT chain ---"
    ip6tables -L INPUT -n -v 2>/dev/null || echo "ip6tables not available."

    echo ""
    echo "--- IP forwarding ---"
    sysctl net.ipv4.ip_forward 2>/dev/null

} > HC_FirewallState.txt

sha1sum HC_FirewallState.txt >> Hashes.txt

###############################
# KERNEL HARDENING PARAMETERS #
###############################

echo "Processing kernel hardening parameters."

{
    echo "=== Kernel Hardening Parameters ==="
    echo "Checked: $(date +"%m-%d-%Y %H:%M:%S")"
    echo ""

    params=(
        "kernel.randomize_va_space"
        "kernel.yama.ptrace_scope"
        "kernel.dmesg_restrict"
        "kernel.kptr_restrict"
        "net.ipv4.tcp_syncookies"
        "net.ipv4.conf.all.accept_redirects"
        "net.ipv4.conf.default.accept_redirects"
        "net.ipv6.conf.all.accept_redirects"
        "net.ipv4.conf.all.send_redirects"
        "net.ipv4.conf.all.rp_filter"
        "net.ipv4.conf.default.rp_filter"
        "net.ipv4.icmp_echo_ignore_broadcasts"
        "net.ipv4.conf.all.log_martians"
        "net.ipv4.conf.all.accept_source_route"
        "fs.suid_dumpable"
        "fs.protected_hardlinks"
        "fs.protected_symlinks"
    )

    for param in "${params[@]}"; do
        val=$(sysctl "$param" 2>/dev/null)
        if [ -n "$val" ]; then
            echo "$val"
        else
            echo "$param = NOT SET"
        fi
    done

} > HC_KernelHardening.txt

sha1sum HC_KernelHardening.txt >> Hashes.txt

########################################
# MAC ENFORCEMENT (SELinux / AppArmor) #
########################################

echo "Processing MAC enforcement status."

{
    echo "=== Mandatory Access Control (MAC) Enforcement ==="
    echo "Checked: $(date +"%m-%d-%Y %H:%M:%S")"
    echo ""

    if command -v getenforce &>/dev/null; then
        echo "--- SELinux ---"
        echo "Mode: $(getenforce 2>/dev/null)"
        echo ""
        if [ -f /etc/selinux/config ]; then
            echo "Config (/etc/selinux/config):"
            cat /etc/selinux/config
        fi
        metafile /etc/selinux/config

    elif command -v aa-status &>/dev/null; then
        echo "--- AppArmor ---"
        aa-status 2>/dev/null

    else
        echo "Neither SELinux nor AppArmor detected on this system."
    fi

} > HC_MACEnforcement.txt

sha1sum HC_MACEnforcement.txt >> Hashes.txt


#########################
# RISKY LEGACY SERVICES #
#########################

echo "Processing risky legacy services."

{
    echo "=== Risky Legacy Services ==="
    echo "Checked: $(date +"%m-%d-%Y %H:%M:%S")"
    echo ""

    risky_services=(telnet ftp rsh rlogin rexec vsftpd xinetd tftp nis rpcbind)

    printf "%-20s %-12s %s\n" "Service" "State" "Note"
    printf "%-20s %-12s %s\n" "--------------------" "------------" "----"

    for svc in "${risky_services[@]}"; do
        state=$(systemctl is-active "$svc" 2>/dev/null)
        if [ -z "$state" ] || [ "$state" = "" ]; then
            state="not-found"
        fi
        printf "%-20s %-12s\n" "$svc" "$state"
    done

    echo ""
    echo "--- inetd / xinetd config (if present) ---"
    for f in /etc/inetd.conf /etc/xinetd.conf; do
        if [ -f "$f" ]; then
            echo "File: $f"
            cat "$f"
            metafile "$f"
        fi
    done

} > HC_RiskyServices.txt

sha1sum HC_RiskyServices.txt >> Hashes.txt

###################
# LISTENING PORTS #
###################

echo "Processing listening ports."

{
    echo "=== Open Listening Ports ==="
    echo "Checked: $(date +"%m-%d-%Y %H:%M:%S")"
    echo ""

    echo "--- ss -tlnp (TCP) ---"
    ss -tlnp 2>/dev/null || echo "ss not available."

    echo ""
    echo "--- ss -ulnp (UDP) ---"
    ss -ulnp 2>/dev/null

    echo ""
    echo "--- All ESTABLISHED connections ---"
    ss -tnp state established 2>/dev/null

} > HC_ListeningPorts.txt

sha1sum HC_ListeningPorts.txt >> Hashes.txt

###############################################
# 10. SYSTEM PATCH STATUS
###############################################

echo "Processing system patch status."

{
    echo "=== System Patch Status ==="
    echo "Checked: $(date +"%m-%d-%Y %H:%M:%S")"
    echo ""

    if command -v apt-get &>/dev/null; then
        echo "--- Package manager: apt ---"
        apt-get -s upgrade 2>/dev/null | grep "^[0-9]* upgraded"
        echo ""
        echo "Pending security updates:"
        apt-get -s upgrade 2>/dev/null | grep -i "security" || echo "None detected."
        echo ""
        echo "--- unattended-upgrades ---"
        dpkg -l unattended-upgrades 2>/dev/null | grep "^ii" \
            && cat /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null \
            || echo "unattended-upgrades not installed."
        metafile /etc/apt/apt.conf.d/50unattended-upgrades

    elif command -v yum &>/dev/null; then
        echo "--- Package manager: yum ---"
        yum check-update --quiet 2>/dev/null | grep -v "^$\|^Last"
        echo ""
        echo "--- yum-cron / dnf-automatic ---"
        systemctl is-active yum-cron 2>/dev/null || systemctl is-active dnf-automatic 2>/dev/null \
            || echo "yum-cron / dnf-automatic not active."

    elif command -v dnf &>/dev/null; then
        echo "--- Package manager: dnf ---"
        dnf check-update --quiet 2>/dev/null | grep -v "^$\|^Last"

    elif command -v zypper &>/dev/null; then
        echo "--- Package manager: zypper ---"
        zypper list-updates 2>/dev/null

    else
        echo "No recognised package manager found."
    fi

} > HC_PatchStatus.txt

sha1sum HC_PatchStatus.txt >> Hashes.txt


###########################
# Other Security Settings #
###########################

echo "Processing other security settings."

# Get sshd config & corresponding hash
cat /etc/ssh/sshd_config > Sshdconfig.txt 
sha1sum Sshdconfig.txt >> Hashes.txt  

# pam_faillock.so
faillock=/etc/security/faillock.conf
if [ -f "$faillock" ]; then
    cat "$faillock" > faillockconfig.txt

    stat -c "%a;%n;%U;%G;%Z;%Y" "$faillock" >> MetaData.txt
	sha1sum faillockconfig.txt >> Hashes.txt
fi

# secure tty
securetty=/etc/securetty
if [ -f "$securetty" ]; then
    cat "$securetty" > securetty.txt
 
    stat -c "%a;%n;%U;%G;%Z;%Y" "$securetty" >> MetaData.txt
    sha1sum securetty.txt >> Hashes.txt   
fi

# login.defs
logindef=/etc/login.defs
if [ -f "$logindef" ]; then
    cat "$logindef" > login.txt
    
    stat -c "%a;%n;%U;%G;%Z;%Y" "$logindef" >> MetaData.txt
	sha1sum login.txt >> Hashes.txt
fi

# host equiv
hostequiv=/etc/hosts.equiv
if [ -f "$hostequiv" ]; then
    cat "$hostequiv" > hostequiv.txt
        
    stat -c "%a;%n;%U;%G;%Z;%Y" "$hostequiv" >> MetaData.txt
    sha1sum hostequiv.txt >> Hashes.txt
fi

# r.host
echo $(sudo ls /home/*/.rhosts 2>/dev/null) > rhosts.txt
sha1sum rhosts.txt >> Hashes.txt

# pam_access
accessconfig=/etc/security/access.conf
if [ -f "$accessconfig" ]; then
    cat "$accessconfig" > accessconfig.txt

    sha1sum accessconfig.txt >> Hashes.txt      
    stat -c "%a;%n;%U;%G;%Z;%Y" "$accessconfig" >> MetaData.txt
fi

# Obtain a list of unique risky services that are actively running
sudo ps ax | grep -Evw 'grep|nis+|nisplus' | grep -Eoi 'ftp|telnet|finger|smtp|tftp|nfs|nis.|dns|bind|rsh|rlogin|rexec' | sort --unique > riskyServices.txt
sha1sum riskyServices.txt >> Hashes.txt

inetdconfig=/etc/inetd.conf
if [ -f "$inetdconfig" ]; then
    cat "$inetdconfig" > inetdConfig.txt

    sha1sum inetdConfig.txt >> Hashes.txt
    stat -c "%a;%n;%U;%G;%Z;%Y" "$inetdconfig" >> MetaData.txt
fi


###################
# System settings #
###################

echo "Processing system settings."

# Get Linux Version
if [ -f /etc/os-release ]; then
    # freedesktop.org and systemd
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
elif type lsb_release >/dev/null 2>&1; then
    # linuxbase.org
    OS=$(lsb_release -si)
    VER=$(lsb_release -sr)
elif [ -f /etc/lsb-release ]; then
    # For some versions of Debian/Ubuntu without lsb_release command
    . /etc/lsb-release
    OS=$DISTRIB_ID
    VER=$DISTRIB_RELEASE
elif [ -f /etc/debian_version ]; then
    # Older Debian/Ubuntu/etc.
    OS=Debian
    VER=$(cat /etc/debian_version)
else
    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
    OS=$(uname -s)
    VER=$(uname -r)
fi

# Get the status change date of several files/directories that should exist on most Linux distributions and get the earliest date for an indication of how old the instance is bare minimum
# This will not necessarily give the Creation Date since all the files might have been modified after the fact, but it will give a good indication of how old the system AT LEAST is
FILES=("/etc/audit" "/etc/hostname" "/etc/passwd" "/etc/group" "/etc/sudoers") 
CREATIONDATE=$(date +%s) 

for file in ${FILES[@]}; do
    if [ -e "$file" ]; then
        date=$(stat --printf='%Y' $file)
        CREATIONDATE=$(($date < $CREATIONDATE ? $date : $CREATIONDATE))
    fi
done

# Create SystemInformation file containing version of script, OS, distribution, Date of script run, hostname of Linux and Linux instance creation date
{
    echo 'Script Version;OS;OS Version;Date of Script run;Hostname;Instance Creation Date';
    echo $version';'$OS';'$VER';'$(date +"%m-%d-%Y %H:%M:%S")';'$HOSTNAME';'$CREATIONDATE;
} > SystemInformation.txt

sha1sum SystemInformation.txt >> Hashes.txt  

#################
# Final cleanup #
#################

sha1sum MetaData.txt >> Hashes.txt

echo "Script running Completed, please zip and copy files."