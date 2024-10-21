# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify
import subprocess
import paramiko
import shlex
import re

app = Flask(__name__)

# Validation d'IP ou nom d'hôte
def validate_ip_or_hostname(host):
    ip_regex = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    hostname_regex = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
    return ip_regex.match(host) or hostname_regex.match(host)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/ping')
def ping_page():
    return render_template('ping.html')

@app.route('/netstat')
def netstat_page():
    return render_template('netstat.html')

@app.route('/config')
def config_page():
    return render_template('config.html')

@app.route('/auto-configuration')
def auto_configuration():
	return render_template('auto-configuration.html')

@app.route('/ping', methods=['POST'])
def ping():
    host = request.form['host']
    if not validate_ip_or_hostname(host):
        return jsonify(success=False, result="Adresse IP ou nom d'hôte invalide.")
    try:
        output = subprocess.check_output(shlex.split(f"ping -c 4 {host}"))
        result = output.decode()
        return jsonify(success=True, result=result)
    except subprocess.CalledProcessError:
        return jsonify(success=False, result="Ping échoué.")

@app.route('/netstat', methods=['POST'])
def netstat_route():
    try:
        output = subprocess.check_output(["netstat", "-i"])
        result = output.decode()
        return jsonify(success=True, result=result)
    except Exception as e:
        return jsonify(success=False, result=str(e))

def enter_enable_mode(client, enable_password):
    """Passe en mode enable si nécessaire pour les routeurs avec privilèges élevés"""
    stdin, stdout, stderr = client.exec_command('enable\n')
    stdin.write(enable_password + '\n')
    stdin.flush()
    stdout.channel.recv_exit_status()

@app.route('/router-config', methods=['POST'])
def router_config():
    ip = request.form['ip']
    username = request.form['username']
    password = request.form['password']
    router_type = request.form['router_type']
    enable_password = request.form.get('enable_password')

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=10)

        # Entrez en mode enable si nécessaire pour les routeurs Cisco
        if router_type == 'cisco' and enable_password:
            enter_enable_mode(client, enable_password)

        # Exécution de la commande en fonction du type de routeur
        if router_type == 'cisco':
            stdin, stdout, stderr = client.exec_command("show running-config")
        elif router_type == 'mikrotik':
            stdin, stdout, stderr = client.exec_command("/export")

        config = stdout.read().decode()
        client.close()
        return jsonify(success=True, result=config)
    except paramiko.AuthenticationException:
        return jsonify(success=False, result="Authentification échouée.")
    except paramiko.SSHException:
        return jsonify(success=False, result="Erreur lors de la connexion SSH.")
    except Exception as e:
        return jsonify(success=False, result=str(e))



# Fonction pour configuration automatique pour Cisco
def cisco_auto_config(ip, username, password, config_type, enable_password=None):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=10)

        # Entrez en mode enable
        if enable_password:
            enter_enable_mode(client, enable_password)

        # Application de la configuration en fonction du type
        if config_type == 'basic':
            commands = [
                "configure terminal",
                "hostname Routeur-Basique",
                "interface Ethernet0",
                "ip address 192.168.1.1 255.255.255.0",
                "no shutdown",
                "ip dhcp pool VLAN1",
                "network 192.168.1.0 255.255.255.0",
                "default-router 192.168.1.1",
                "dns-server 8.8.8.8",
                "end"
            ]
        elif config_type == 'advanced':
            commands = [
                "configure terminal",
                "hostname Routeur-Avance",
                "interface Ethernet0/0",
                "ip address 10.0.0.1 255.255.255.0",
                "no shutdown",
                "ip dhcp pool DATA_POOL",
                "network 10.0.0.0 255.255.255.0",
                "default-router 10.0.0.1",
                "dns-server 8.8.8.8",
                "ip route 0.0.0.0 0.0.0.0 10.0.0.254",
                "end"
            ]

        # Exécution des commandes sur le routeur Cisco
        for command in commands:
            stdin, stdout, stderr = client.exec_command(command)
            stdout.channel.recv_exit_status()

        client.close()
        return "Configuration Cisco appliquée avec succès."
    except Exception as e:
        return str(e)

# Fonction pour configuration automatique pour MikroTik
def mikrotik_auto_config(ip, username, password, config_type):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=10)

        if config_type == 'basic':
            commands = [
                "/interface bridge add name=bridge1",
                "/ip address add address=192.168.88.1/24 interface=bridge1",
                "/ip dhcp-server setup interface=bridge1",
                "/ip dhcp-server network add address=192.168.88.0/24 gateway=192.168.88.1 dns-server=8.8.8.8"
            ]
        elif config_type == 'advanced':
            commands = [
                "/interface bridge add name=bridge1",
                "/ip address add address=10.0.0.1/24 interface=bridge1",
                "/ip dhcp-server setup interface=bridge1",
                "/ip dhcp-server network add address=10.0.0.0/24 gateway=10.0.0.1 dns-server=8.8.8.8",
                "/ip route add dst-address=0.0.0.0/0 gateway=10.0.0.254"
            ]

        # Exécution des commandes sur le routeur MikroTik
        for command in commands:
            stdin, stdout, stderr = client.exec_command(command)
            stdout.channel.recv_exit_status()

        client.close()
        return "Configuration MikroTik appliquée avec succès."
    except Exception as e:
        return str(e)

# Route pour la configuration automatique
@app.route('/auto-configuration', methods=['POST'])
def auto_configuration_route():
    ip = request.form['ip']
    username = request.form['username']
    password = request.form['password']
    enable_password = request.form.get('enable_password')
    config_type = request.form['config_type']
    router_type = request.form['router_type']

    if router_type == 'cisco':
        result = cisco_auto_config(ip, username, password, config_type, enable_password)
    elif router_type == 'mikrotik':
        result = mikrotik_auto_config(ip, username, password, config_type)
    else:
        result = "Type de routeur non reconnu."

    return jsonify(success=True, result=result)

# Route pour la configuration manuelle
@app.route('/manual-configuration', methods=['POST'])
def manual_configuration_route():
    ip = request.form['ip']
    username = request.form['username']
    password = request.form['password']
    enable_password = request.form.get('enable_password')
    commands = request.form['manual_commands'].splitlines()
    router_type = request.form['router_type']

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=10)

        if enable_password:
            enter_enable_mode(client, enable_password)

        for command in commands:
            stdin, stdout, stderr = client.exec_command(command)
            stdout.channel.recv_exit_status()

        client.close()
        return jsonify(success=True, result="Les commandes ont été exécutées avec succès.")
    except Exception as e:
        return jsonify(success=False, result=str(e))

@app.route('/show-running-config', methods=['POST'])
def show_running_config():
    ip = request.form['ip']
    username = request.form['username']
    password = request.form['password']
    router_type = request.form['router_type']
    enable_password = request.form.get('enable_password')

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=10)

        # Entrez en mode enable si nécessaire pour les routeurs Cisco
        if router_type == 'cisco' and enable_password:
            enter_enable_mode(client, enable_password)

        # Exécution de la commande en fonction du type de routeur
        if router_type == 'cisco':
            stdin, stdout, stderr = client.exec_command("show running-config")
        elif router_type == 'mikrotik':
            stdin, stdout, stderr = client.exec_command("/export")

        config = stdout.read().decode()
        client.close()
        return jsonify(success=True, result=config)
    except paramiko.AuthenticationException:
        return jsonify(success=False, result="Authentification échouée.")
    except paramiko.SSHException:
        return jsonify(success=False, result="Erreur lors de la connexion SSH.")
    except Exception as e:
        return jsonify(success=False, result=str(e))

if __name__ == '__main__':
    app.run(debug=True)
