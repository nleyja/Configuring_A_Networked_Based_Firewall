# Configuring_A_Networked_Based_Firewall

Conduct network security practices using the pfSense VM.

### Objectives

Install and configure network components, both hardware and software-based,
to support organizational security

Given a scenario, implement secure network architecture

## Configuring ICMP on the Firewall

Configuring ICMP on the Firewall: Summary

1. Launch Virtual Machines:
- Start Ubuntu VM, log in as student.
- Open terminal, ping Kali system (203.0.113.2).
 - Start Kali VM, log in as root, open terminal, ping Ubuntu system (192.168.1.50).
- Access pfSense interface via Firefox (http://192.168.1.1).
2. Configure Firewall Rules:
- In pfSense, navigate to Firewall > Rules.
- On EXTERNAL_GW tab, add a new rule.
- Action: Block, Protocol: ICMP, Source Type: Network (203.0.113.0/29).
- Save changes, apply, and verify the rule.
3. Ping Test:
- On Kali, attempt to ping Ubuntu system (192.168.1.50).
- Result: 4 packets transmitted, 0 received due to firewall rule.

#### Blocking ICMP Requests on pfSense
![Login](https://github.com/nleyja/Configuring_a_NetBased_Firewall/blob/main/Lab%2011%20-%20Configuring%20a%20Network-Bsed%20Firewall1_NL.jpg?raw=true)

## Redirecting Traffic to Internal Hosts: Summary

1. Port Scanning:
- On Kali system, scan firewall appliance for open ports using nmap 203.0.113.
2. Configuring pfSense:
- On Ubuntu, access pfSense interface in Firefox.
- Navigate to Firewall > NAT, add new rule:
- Destination port range: SSH (from and to).
- Redirect Target IP: 192.168.1.50.
- Redirect Target Port: SSH.
- Save changes, apply, and confirm configuration.

#### Configuring pfSense to Allow a Port and Redirect Requests

![Login](https://github.com/nleyja/Configuring_a_NetBased_Firewall/blob/main/Lab%2011%20-%20Configuring%20a%20Network-Bsed%20Firewall2_NL.jpg?raw=true)


## Retargeted SSH Connection: Summary

1. Port Scanning:
- On Kali system, scan firewall appliance for open ports: nmap 203.0.113.1.
2. SSH Configuration Verification:
- SSH into 203.0.113.1 (password: securepassword) to confirm SSH access.
- Verify open ports, confirming SSH accessibility.
3. Network Verification:
- On Ubuntu, check network configuration: ifconfig and default gateway: route.
- Scan internal network ports using: nmap 192.168.1.1.


#### Retargeted SSH Connection
![Login](https://github.com/nleyja/Configuring_a_NetBased_Firewall/blob/main/Lab%2011%20-%20Configuring%20a%20Network-Bsed%20Firewall3_NL.jpg?raw=true)


## Configuring VPN on pfSense: Summary

1. Certificate Authority Setup:
- Create an internal Certificate Authority (CA) in pfSense.
- Configure CA details: Descriptive Name, Method, Key Length, Distinguished Name.
- Save the CA settings.
2. Server Certificate Configuration:
- Add a server certificate linked to the created CA.
- Configure certificate details: Descriptive Name, Certificate Authority, Key Length, Certificate Type, Distinguished Name.
- Save the server certificate settings.
3. User Creation:
- Create a new user in pfSense.
- Set username, password, and configure a user certificate.
- Associate the user certificate with the previously created CA.
3. VPN Server Configuration:
- Navigate to VPN > OpenVPN in pfSense.
- Run the VPN Server setup wizard.
- Configure server details: Interface, Protocol, Local Port, Description, Cryptographic Settings, Tunnel Settings, Client Settings.
- Set up firewall rules and complete the configuration.

#### Configuring VPN Server

![Login](https://github.com/nleyja/Configuring_a_NetBased_Firewall/blob/main/Lab%2011%20-%20Configuring%20a%20Network-Bsed%20Firewall4_NL.jpg?raw=true)


## Exporting VPN Client Data: Summary

1. Access VPN Settings:
- Access pfSense webConfigurator, navigate to VPN > OpenVPN.
2. Client Export Configuration:
- Verify server settings: Remote Access Server, Host Name Resolution, Very Server CN, Use Random Local Port.
- Enable password protection for the pkcs12 file, using 'bpassx' as the password.
3. Export Client Package:
- Scroll down to the Client Install Packages table.
- Click on the "Archive" link for Standard Configurations under the Export column.
- Download the file by selecting "Save File" and clicking OK.

#### Exporting VPN Client Data

![Login](https://github.com/nleyja/Configuring_a_NetBased_Firewall/blob/main/Lab%2011%20-%20Configuring%20a%20Network-Bsed%20Firewall5_NL.jpg?raw=true)

## Configuring VPN Client: Summary

1. Prepare for Configuration:
- Change directory to Downloads: cd /home/student/Downloads.
- Unzip the downloaded configuration file: unzip pfsense-udp-1194-student-config.zip.
2. Network Manager Setup:
- Open Network Manager, go to VPN Connections > Configure VPN.
- Click "Import" and navigate to the unzipped folder.
- Select the pfsense-udp-1194-student.ovpn file and open it.
3. Configuration Details:
- Set Gateway to 192.168.1.1.
- Authentication Type: Password with Certificate (TLS).
- User name: student.
- Password: bpassx.
- Verify certificates and private key entries.
- Save configurations as per the provided image.
4. Completion:
- Verify settings and click "Save."
- Close the Network Connections window.

#### Configuring VPN Client

![Login](https://github.com/nleyja/Configuring_a_NetBased_Firewall/blob/main/Lab%2011%20-%20Configuring%20a%20Network-Bsed%20Firewall6_NL.jpg?raw=true)

## Connecting the VPN Client: Summary

1. Connect to VPN:
- Click Network Manager icon, go to VPN Connection > pfsense-udp-1194-student.
2. Verification:
- Verify VPN tunnel and assigned IP address: ifconfig in terminal.

#### Connecting the VPN Client
![Login](https://github.com/nleyja/Configuring_a_NetBased_Firewall/blob/main/Lab%2011%20-%20Configuring%20a%20Network-Bsed%20Firewall8_NL.jpg?raw=true)


## Managing VPN Connections: Summary

1. Access pfSense Web Configurator:
- While connected to VPN, open Firefox and go to pfSense Web Configurator.
2. Check System Logs:
- Log in as admin and navigate to Status > System Logs.
- Select the OpenVPN tab to view authentication steps.
3. Monitor Active Connections:
- Go to Status > OpenVPN to view active VPN connections.
4. Completion:
The lab is complete; you can end the session.

#### Managing VPN Connections

![Login](https://github.com/nleyja/Configuring_a_NetBased_Firewall/blob/main/Lab%2011%20-%20Configuring%20a%20Network-Bsed%20Firewall9_NL.jpg?raw=true)
