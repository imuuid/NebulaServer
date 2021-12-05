using System;
using WebSocketSharp.Server;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

class Program
{
    public static WebSocketServer server = new WebSocketServer(4649);
    public static List<string> bannedHw, bannedIP;
    public static List<Client> nebulaSpammerClients;

    public static void DeleteAccount(ServiceType serviceType, string username, string password, string hardwareID, string ipAddress)
    {
        string builtFile = "", fileName = GetFileNameFromService(serviceType);

        foreach (string line in System.IO.File.ReadAllLines(fileName))
        {
            if (line.Replace(" ", "").Trim().Replace('\t'.ToString(), "") == "")
            {
                continue;
            }

            dynamic jss = JObject.Parse(line);

            string readUsername = (string)jss.u;
            string readPassword = (string)jss.p;
            string readHardwareID = (string)jss.h;
            string readIpAddress = (string)jss.i;

            if (readUsername == username || readPassword == password || readHardwareID == hardwareID || readIpAddress == ipAddress)
            {
                continue;
            }
            else
            {
                string hwidToWrite = "";

                if (readHardwareID == "")
                {
                    hwidToWrite = "null";
                }
                else
                {
                    hwidToWrite = "\"" + readHardwareID + "\"";
                }

                string ipToWrite = "";

                if (readIpAddress == "")
                {
                    ipToWrite = "null";
                }
                else
                {
                    ipToWrite = "\"" + readIpAddress + "\"";
                }

                if (builtFile == "")
                {
                    builtFile = "{\"u\": \"" + readUsername + "\", \"p\": \"" + readPassword + "\", \"h\": " + hwidToWrite + ", \"i\": " + ipToWrite + "}";
                }
                else
                {
                    builtFile += Environment.NewLine + "{\"u\": \"" + readUsername + "\", \"p\": \"" + readPassword + "\", \"h\": " + hwidToWrite + ", \"i\": " + ipToWrite + "}";
                }
            }
        }

        System.IO.File.WriteAllText(fileName, builtFile);
    }

    public static string GetFileNameFromService(ServiceType serviceType)
    {
        if (serviceType.Equals(ServiceType.NebulaSpammer))
        {
            return "nebula-spammer-credentials.txt";
        }

        return "";
    }

    public static byte CheckCredentials(ServiceType serviceType, string username, string password, string hardwareID, string ipAddress)
    {
        byte loginStatus = 0;
        string builtFile = "", fileName = GetFileNameFromService(serviceType);
        int hwidTimes = 0, ipTimes = 0;

        foreach (string line in System.IO.File.ReadAllLines(fileName))
        {
            if (line.Replace(" ", "").Trim().Replace('\t'.ToString(), "") == "")
            {
                continue;
            }

            byte actualLoginStatus = 0;
            dynamic jss = JObject.Parse(line);

            string readUsername = (string)jss.u;
            string readPassword = (string)jss.p;
            string readHardwareID = (string)jss.h;
            string readIpAddress = (string)jss.i;

            if (readHardwareID == "")
            {
                readHardwareID = "null";
            }
            
            if (readIpAddress == "")
            {
                readIpAddress = "null";
            }

            if (readHardwareID == hardwareID)
            {
                hwidTimes++;
            }

            if (ipAddress == readIpAddress)
            {
                ipTimes++;
            }

            if (readHardwareID == null || readHardwareID.ToLower() == "null" || readHardwareID == "")
            {
                if (readUsername == username && readPassword == password)
                {
                    loginStatus = 2;
                    actualLoginStatus = 2;
                }
            }
            else
            {
                if (readUsername == username && readPassword == password)
                {
                    if (readHardwareID != hardwareID)
                    {
                        loginStatus = 0;
                    }
                    else
                    {
                        loginStatus = 2;
                        actualLoginStatus = 2;
                    }
                }
            }

            if (actualLoginStatus == 2)
            {
                readHardwareID = hardwareID;
                readIpAddress = ipAddress;
            }

            string hwidToWrite = "";

            if (readHardwareID == "")
            {
                hwidToWrite = "null";
            }
            else
            {
                hwidToWrite = "\"" + readHardwareID + "\"";
            }

            string ipToWrite = "";

            if (readIpAddress == "")
            {
                ipToWrite = "null";
            }
            else
            {
                ipToWrite = "\"" + readIpAddress + "\"";
            }

            if (hwidToWrite == "\"\"")
            {
                hwidToWrite = "null";
            }

            if (ipToWrite == "\"\"")
            {
                ipToWrite = "null";
            }

            if (builtFile == "")
            {
                builtFile = "{\"u\": \"" + readUsername + "\", \"p\": \"" + readPassword + "\", \"h\": " + hwidToWrite + ", \"i\": " + ipToWrite + "}";
            }
            else
            {
                builtFile += Environment.NewLine + "{\"u\": \"" + readUsername + "\", \"p\": \"" + readPassword + "\", \"h\": " + hwidToWrite + ", \"i\": " + ipToWrite + "}";
            }
        }

        if (hwidTimes > 1 || ipTimes > 1)
        {
            loginStatus = 1;
        }

        System.IO.File.WriteAllText(fileName, builtFile);

        return loginStatus;
    }

    public static void banHardware(string hw)
    {
        if (hw.Replace(" ", "").Replace('\t'.ToString(), "") == "")
        {
            return;
        }

        if (bannedHw.Contains(hw))
        {
            return;
        }

        bannedHw.Add(hw);
        string txt = System.IO.File.ReadAllText("banned-hardwares.txt");

        if (txt.Replace(" ", "").Replace('\t'.ToString(), "") == "")
        {
            txt = hw;
        }
        else
        {
            txt += Environment.NewLine + hw;
        }

        System.IO.File.WriteAllText("banned-hardwares.txt", txt);

        List<Client> toRemove = new List<Client>();

        foreach (Client client in nebulaSpammerClients)
        {
            if (client.hardwareId.ToLower().Equals(hw.ToLower()))
            {
                toRemove.Add(client);
            }
        }

        foreach (Client clientToRemove in toRemove)
        {
            nebulaSpammerClients.Remove(clientToRemove);
        }

        Console.WriteLine("[!] Banned Hardware ID for violation: " + hw + ".");
    }

    public static void banIP(string hw)
    {
        bannedIP.Add(hw);
        string txt = System.IO.File.ReadAllText("banned-ips.txt");

        if (txt.Replace(" ", "").Replace('\t'.ToString(), "") == "")
        {
            txt = hw;
        }
        else
        {
            txt += Environment.NewLine + hw;
        }

        System.IO.File.WriteAllText("banned-ips.txt", txt);
        List<Client> toRemove = new List<Client>();

        foreach (Client client in nebulaSpammerClients) 
        {
            if (client.ipAddress.ToLower().Equals(hw.ToLower()))
            {
                toRemove.Add(client);
            }
        }

        foreach (Client clientToRemove in toRemove)
        {
            nebulaSpammerClients.Remove(clientToRemove);
        }

        Console.WriteLine("[!] Banned IP Address for violation: " + hw + ".");
    }

    public static void Main()
    {
        bannedHw = new List<string>();
        bannedIP = new List<string>();

        nebulaSpammerClients = new List<Client>();

        if (!System.IO.File.Exists("banned-hardwares.txt"))
        {
            System.IO.File.WriteAllText("banned-hardwares.txt", "");
        }
        else
        {
            foreach (string bannedHardware in System.IO.File.ReadAllLines("banned-hardwares.txt"))
            {
                bannedHw.Add(bannedHardware);
            }
        }

        if (!System.IO.File.Exists("banned-ips.txt"))
        {
            System.IO.File.WriteAllText("banned-ips.txt", "");
        }
        else
        {
            foreach (string ip in System.IO.File.ReadAllLines("banned-ips.txt"))
            {
                bannedIP.Add(ip);
            }
        }

        Console.WriteLine("[!] Starting server...");

        server.KeepClean = false;
        server.SslConfiguration.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12;
        server.AuthenticationSchemes = WebSocketSharp.Net.AuthenticationSchemes.Anonymous;

        server.AddWebSocketService<NebulaSpammer>("/NebulaSpammer");

        server.Start();

        Console.WriteLine("[!] Server started!");
        Console.ReadLine();

        server.Stop();
    }
}