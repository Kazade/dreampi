#include <iostream>
#include <string>
#include <cstdlib>
#include <fstream>
using namespace std;

void AddWifiNetwork(string SSID, string WifiPass)
{
	
	ofstream WPASupplicant("/etc/wpa_supplicant/wpa_supplicant.conf", ios_base::app);
	if (WPASupplicant.is_open())
	{			
		WPASupplicant << endl << "network={" << endl;
		WPASupplicant << "ssid=\"" + SSID + "\"" << endl;
		WPASupplicant << "psk=\"" + WifiPass + "\"" << endl;
		WPASupplicant << "}";
		WPASupplicant.close();
		cout << endl;
		cout << "The wireless network '" + SSID + "' " + "has been added." << endl;		
	}
	else
	{
		cout << "Unable to open the network config file. Please run 'sudo wificonfig' and try again." << endl; 
	}
	
}

void AddOpenWifiNetwork(string SSID)
{
	
	ofstream WPASupplicant("/etc/wpa_supplicant/wpa_supplicant.conf", ios_base::app);
	if (WPASupplicant.is_open())
	{			
		WPASupplicant << endl << "network={" << endl;
		WPASupplicant << "ssid=\"" + SSID + "\"" << endl;
		WPASupplicant << "key_mgmt=NONE" << endl;
		WPASupplicant << "}";
		WPASupplicant.close();
		cout << endl;
		cout << "The wireless network '" + SSID + "' " + "has been added." << endl;		
	}
	else
	{
		cout << "Unable to open the network config file. Please run 'sudo wificonfig' and try again." << endl; 
	}
	
}

void EnableWifi()
{
	ofstream WPASupplicant("/etc/network/interfaces");
	if (WPASupplicant.is_open())
	{			
		WPASupplicant << "auto wlan0" << endl;
		WPASupplicant << "allow-hotplug wlan0" << endl;
		WPASupplicant << "iface wlan0 inet manual" << endl;
		WPASupplicant << "wpa-roam /etc/wpa_supplicant/wpa_supplicant.conf" << endl;
		WPASupplicant << "iface default inet dhcp" << endl;
		WPASupplicant << "dns-nameserver 127.0.0.1" << endl << endl;
		
		WPASupplicant << "manual eth0" << endl;
		WPASupplicant << "allow-hotplug eth0" << endl;
		WPASupplicant << "iface eth0 inet dhcp" << endl;
		WPASupplicant << "dns-nameserver 127.0.0.1";
		WPASupplicant.close();
	}
	else
	{
		cout << "Unable to open the interfaces config file. Please run 'sudo wificonfig' and try again." << endl; 
	}

	//Enable Pi 3 internal Wi-Fi (if disabled) in config.txt by reverting to defaults
	ofstream bootconf("/boot/config.txt");
	if (bootconf.is_open())
	{					
		bootconf << "config_hdmi_boost=4" << endl;
		bootconf << "hdmi_force_hotplug=1" << endl;
		bootconf << "hdmi_drive=2" << endl;
		bootconf.close();
		cout << "Wi-Fi has been enabled. Please reboot the Pi for the changes to take effect." << endl;
	}
	else
	{
		cout << "Unable to open the boot config file. Please run 'sudo wificonfig' and try again." << endl; 
	}
}

void DisableWifi()
{
	//Reset interfaces to the default configuration
	ofstream WPASupplicant("/etc/network/interfaces");
	if (WPASupplicant.is_open())
	{					
		WPASupplicant << "auto eth0" << endl;
		WPASupplicant << "allow-hotplug eth0" << endl;
		WPASupplicant << "iface eth0 inet dhcp" << endl;
		WPASupplicant << "dns-nameserver 127.0.0.1";
		WPASupplicant.close();
	}
	else
	{
		cout << "Unable to open the Wi-Fi config file. Please run 'sudo wificonfig' and try again." << endl; 
	}

	//Disable Pi 3 internal Wi-Fi in config.txt
	ofstream bootconf("/boot/config.txt");
	if (bootconf.is_open())
	{					
		bootconf << "config_hdmi_boost=4" << endl;
		bootconf << "hdmi_force_hotplug=1" << endl;
		bootconf << "hdmi_drive=2" << endl;
		bootconf << "dtoverlay=pi3-disable-wifi";
		bootconf.close();
		cout << "Wi-Fi has been disabled. Please reboot the Pi for the changes to take effect." << endl;
	}
	else
	{
		cout << "Unable to open the boot config file. Please run 'sudo wificonfig' and try again." << endl; 
	}
}

void EraseNetworks()
{	
	ofstream WPASupplicant("/etc/wpa_supplicant/wpa_supplicant.conf", ofstream::out | ofstream::trunc);
	if (WPASupplicant.is_open())
	{			
		WPASupplicant.close();
		cout << "All Wi-Fi networks have been erased." << endl;
	}
	else
	{
		cout << "Unable to open the network config file. Please run 'sudo wificonfig' and try again." << endl; 
	}	
}

int main(int argc, char *argv[])
{
	int Selection;
	string UserInput;
	string WifiPass;
	string SSID;
	
	cout << "Welcome to the Wi-Fi configuration wizard!" << endl << endl;
	cout << "Please select an option:" << endl;
	cout << "[1] Enable Wi-Fi" << endl;
	cout << "[2] Disable Wi-Fi" << endl;
	cout << "[3] Add Wi-Fi Network" << endl;
	cout << "[4] Remove Wi-Fi Networks" << endl;
	cout << "[5] Exit" << endl;
	
	cin >> Selection;
		
	switch (Selection)
	{
	case 1:
		
		EnableWifi();
		break;
		
	case 2:
		
		DisableWifi();
		break;
		
	case 3:
		
		cout << "Please select a network type:" << endl;
		cout << "[1] Secured (has password)" << endl;
		cout << "[2] Open (no password)" << endl;		
		
		cin >> Selection;
		
		switch (Selection)
		{
			
		case 1:
			
enterssid:
			cout << "Enter Network Name (SSID): ";
			cin >> SSID;		
			cout << "Enter password: ";
			cin >> WifiPass;
			cout << endl;
confirm:	
			cout << "Is the above information correct? Y/N ";
			cin >> UserInput;
		
			if (UserInput == "Y" || UserInput == "y")
			{			
				AddWifiNetwork(SSID, WifiPass);
				EnableWifi();
			}
			else if (UserInput == "N" || UserInput == "n")
			{
				cout << endl;
				goto enterssid;
			}		
			else
			{
				cout << endl;
				goto confirm;
			}
			break;
			
		case 2:
			
enterssid2:
			cout << "Enter Network Name (SSID): ";
			cin >> SSID;		
			cout << endl;
confirm2:	
			cout << "Is the above information correct? Y/N ";
			cin >> UserInput;
		
			if (UserInput == "Y" || UserInput == "y")
			{			
				AddOpenWifiNetwork(SSID);
				EnableWifi();
			}
			else if (UserInput == "N" || UserInput == "n")
			{
				cout << endl;
				goto enterssid2;
			}		
			else
			{
				cout << endl;
				goto confirm2;
			}
			
		}		
		break;
		
	case 4:
	
confirmation:
		cout << "Are you sure? This will erase all Wi-Fi networks. Y/N";
		cin >> UserInput;
		
		if (UserInput == "Y" || UserInput == "y")
		{			
			EraseNetworks();
		}
		else if (UserInput == "N" || UserInput == "n")
		{
			cout << "Operation aborted. Exited wizard." << endl;
			break;
		}		
		else
		{
			cout << endl;
			goto confirmation;
		}
		
	case 5:
	
		cout << "Exited wizard." << endl;
		break;
		
	default:
		
		cout << "That wasn't one of the options! Exited wizard." << endl;
	}
	
	return 0;
	
}

