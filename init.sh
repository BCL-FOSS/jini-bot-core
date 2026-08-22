#!/bin/sh

firewallconfig() {
  echo "Updating package list and installing persistent tools..."
  apt update -y
  if ! dpkg -l | grep -qE "netfilter-persistent|iptables-persistent"; then
    apt install -y iptables-persistent
    if [ $? -ne 0 ]; then
      echo "Failed to install 'iptables-persistent'. Trying 'netfilter-persistent'..."
      apt install -y netfilter-persistent
      if [ $? -ne 0 ]; then
        echo "Failed to install both 'iptables-persistent' and 'netfilter-persistent'. Exiting."
        exit 1
      fi
    fi
  else
    echo "'iptables-persistent' or 'netfilter-persistent' is already installed."
  fi

  #echo "Flushing existing iptables rules..."
  #iptables -F
  #iptables -X
  #iptables -t nat -F
  #iptables -t nat -X
  #iptables -t mangle -F
  #iptables -t mangle -X

  echo "Allowing traffic on ports 22 (SSH), 80 (HTTP) and 443 (HTTPS)..."
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  iptables -A INPUT -p tcp --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT
  

  echo "Allowing established and related connections..."
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  #echo "Dropping all other incoming traffic..."
  #iptables -P INPUT DROP
  #iptables -P FORWARD DROP
  #iptables -P OUTPUT ACCEPT

  echo "Saving iptables rules..."
  iptables-save > /etc/iptables/rules.v4

  echo "Making iptables rules persistent..."
  netfilter-persistent save
  netfilter-persistent reload

  echo "Disabling UFW..."
  ufw disable

  echo "Configuration complete. Ports 80 and 443 are now open, and UFW is disabled."
}

dockersetup() {

  for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done

  # Add Docker's official GPG key:
  sudo apt-get update
  sudo apt-get install ca-certificates curl
  sudo install -m 0755 -d /etc/apt/keyrings
  sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  sudo chmod a+r /etc/apt/keyrings/docker.asc

  # Add the repository to Apt sources:
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
  sudo apt-get update

  sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

  sudo apt install docker-compose -y

  sudo docker-compose build --no-cache 

  sudo docker volume create --name=client_sess_data
  sudo docker volume create --name=client_auth_data
  sudo docker volume create --name=client_data
  sudo docker volume create --name=rate_limit_data
  sudo docker volume create --name=caddy_data
  sudo docker volume create --name=caddy_config
  sudo docker volume create --name=ollama_models
  sudo docker volume create --name=jini_data
  sudo docker volume create --name=backend_data
  sudo docker volume create --name=ip_ban_data
  sudo docker-compose up
}

sudo apt-get update -y
sudo apt-get upgrade -y

firewallconfig
dockersetup

