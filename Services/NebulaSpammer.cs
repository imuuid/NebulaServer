using System;
using WebSocketSharp;
using WebSocketSharp.Server;
using Newtonsoft.Json.Linq;
using Microsoft.VisualBasic;

public class NebulaSpammer : WebSocketBehavior
{
    protected override void OnOpen()
    {
        Client client = new Client(ID, Context.UserEndPoint.Address.ToString());

        if (Context.UserEndPoint.Address.ToString() == "localhost" || Context.UserEndPoint.Address.ToString() == "0.0.0.0" || Context.UserEndPoint.Address.ToString() == "127.0.0.1" || Context.UserEndPoint.Address.ToString().StartsWith("192.168."))
        {
            Sessions.CloseSession(ID);
            return;
        }

        foreach (string ip in Program.bannedIP)
        {
            if (ip.Equals(client.ipAddress))
            {
                Console.WriteLine("[NebulaSpammer] Blocked a banned IP Address from joining this WS: " + client.ipAddress + ". Tried to join with Session ID: " + ID + ".");
                Sessions.CloseSession(ID);

                return;
            }
        }

        Program.nebulaSpammerClients.Add(client);
        Console.WriteLine("[NebulaSpammer] Client succesfully connected: " + client.wsSessionId + ". IP Address: " + client.ipAddress + ". Waiting for a PACKET_PRESENTATION.");
    }

    protected override void OnClose(CloseEventArgs e)
    {
        Client toRemove = null;
        string hwId = "", ip = "";

        foreach (Client client in Program.nebulaSpammerClients)
        {
            if (client.wsSessionId == ID)
            {
                toRemove = client;
                hwId = client.hardwareId;
                ip = client.ipAddress;

                break;
            }
        }

        if (hwId != "" && ip != "")
        {
            Console.WriteLine("[NebulaSpammer] Session with ID ('" + ID + "') disconnected with Hardware ID ('" + hwId + "') and IP Address ('" + ip + "').");
            Program.nebulaSpammerClients.Remove(toRemove);
        }
    }

    protected override void OnMessage(MessageEventArgs e)
    {
        try
        {
            string msg = "";
            Client client = null;

            foreach (Client theClient in Program.nebulaSpammerClients)
            {
                if (theClient.wsSessionId == ID)
                {
                    client = theClient;
                    break;
                }
            }

            if (Program.bannedHw.Contains(client.hardwareId))
            {
                Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                Sessions.CloseSession(client.wsSessionId);
                Program.banIP(client.ipAddress);
                return;
            }

            if (Program.bannedIP.Contains(client.ipAddress))
            {
                Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                Sessions.CloseSession(client.wsSessionId);
                Program.banHardware(client.hardwareId);
                return;
            }

            if (!client.CAN_DO)
            {
                Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_1.");
                Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                Sessions.CloseSession(client.wsSessionId);
                Program.banIP(client.ipAddress);
                Program.banHardware(client.hardwareId);
                return;
            }

            client.packets++;

            if (client.packets >= 4)
            {
                Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_2.");
                Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                Sessions.CloseSession(client.wsSessionId);
                Program.banIP(client.ipAddress);
                Program.banHardware(client.hardwareId);
                return;
            }

            try
            {
                msg = Utils.CustomDecrypt(e.Data);
            }
            catch
            {
                Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_3.");

                try
                {
                    msg = msg.Replace(" ", "").Replace('\t'.ToString(), "");
                    string[] splitted = Strings.Split("\"h\":");
                    string hardware = Strings.Split(splitted[1], "\"")[0];
                    Program.banHardware(hardware);
                }
                catch
                {

                }

                Sessions.CloseSession(client.wsSessionId);
                Program.banIP(client.ipAddress);
                Program.banHardware(client.hardwareId);
                return;
            }

            if (msg.Replace(" ", "") == "")
            {
                Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_4.");
                Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                Sessions.CloseSession(client.wsSessionId);
                Program.banIP(client.ipAddress);
                Program.banHardware(client.hardwareId);
                return;
            }

            foreach (string hw in Program.bannedHw)
            {
                if (msg.ToLower().Contains(hw.ToLower()))
                {
                    Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_5.");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                    Sessions.CloseSession(client.wsSessionId);
                    Program.banIP(client.ipAddress);
                    Program.banHardware(client.hardwareId);
                    return;
                }
            }

            try
            {
                var theOBJ = JObject.Parse(msg);
            }
            catch
            {
                Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_6.");
                Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);

                try
                {
                    msg = msg.Replace(" ", "").Replace('\t'.ToString(), "");
                    string[] splitted = Strings.Split(msg, "\"h\":");
                    string hardware = Strings.Split(splitted[1], "\"")[0];
                    Program.banHardware(hardware);
                    Sessions.CloseSession(client.wsSessionId);
                    Program.banIP(client.ipAddress);
                }
                catch
                {
                    Sessions.CloseSession(client.wsSessionId);
                    Program.banIP(client.ipAddress);
                    Program.banHardware(client.hardwareId);
                }

                return;
            }

            dynamic jss = JObject.Parse(msg);

            try
            {
                int requestType = (int)jss.t;
                string hardwareID = (string)jss.h;
                long range = (long)jss.r;
                string randomString = (string)jss.s;
                string application = (string)jss.a;
                string version = (string)jss.v;
                string packetType = (string)jss.p;
                string timestamp = (string)jss.m;

                if (hardwareID.ToString().Length <= 0)
                {
                    Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_7.");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                    Sessions.CloseSession(client.wsSessionId);
                    Program.banIP(client.ipAddress);
                    Program.banHardware(client.hardwareId);
                    return;
                }

                if (range.ToString().Length != 10)
                {
                    Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_8.");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                    Sessions.CloseSession(client.wsSessionId);
                    Program.banHardware(hardwareID);
                    Program.banIP(client.ipAddress);
                    return;
                }

                if (randomString.Length != 19)
                {
                    Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_10.");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                    Sessions.CloseSession(client.wsSessionId);
                    Program.banHardware(hardwareID);
                    Program.banIP(client.ipAddress);
                    return;
                }


                if (!TimestampUtils.IsTimestampValid(timestamp))
                {
                    Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_11.");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                    Sessions.CloseSession(client.wsSessionId);
                    Program.banHardware(hardwareID);
                    Program.banIP(client.ipAddress);
                    return;
                }

                if (application != "NEBULA_SPAMMER")
                {
                    Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_12.");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                    Sessions.CloseSession(client.wsSessionId);
                    Program.banHardware(hardwareID);
                    Program.banIP(client.ipAddress);
                    return;
                }

                if (version == "RELEASE_V1.0")
                {
                    Console.WriteLine("[NebulaSpammer] SHA 1 Hash: " + ((string) jss.y) + ", file length: " + ((string) jss.f) + ".");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 8, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_CLOSE_WARNING\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\", \"l\": \"There is a new version available! Join our Discord Server to download it: https://discord.gg/qg6YbDDfFz\", \"j\": \"New version\"}")), ID);
                    return;
                }
                else if (version == "RELEASE_V2.0")
                {
                    Console.WriteLine("[NebulaSpammer] SHA 1 Hash: " + ((string)jss.y) + ", file length: " + ((string)jss.f) + ".");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 8, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_CLOSE_WARNING\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\", \"l\": \"There is a new version available! Join our Discord Server to download it: https://discord.gg/qg6YbDDfFz\", \"j\": \"New version\"}")), ID);
                    return;
                }
                else if (version == "RELEASE_V3.0")
                {
                    Console.WriteLine("[NebulaSpammer] SHA 1 Hash: " + ((string)jss.y) + ", file length: " + ((string)jss.f) + ".");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 8, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_CLOSE_WARNING\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\", \"l\": \"There is a new version available! Join our Discord Server to download it: https://discord.gg/qg6YbDDfFz\", \"j\": \"New version\"}")), ID);
                    return;
                }
                else if (version == "RELEASE_V4.0")
                {
                    Console.WriteLine("[NebulaSpammer] SHA 1 Hash: " + ((string)jss.y) + ", file length: " + ((string)jss.f) + ".");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 8, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_CLOSE_WARNING\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\", \"l\": \"There is a new version available! Join our Discord Server to download it: https://discord.gg/qg6YbDDfFz\", \"j\": \"New version\"}")), ID);
                    return;
                }
                else if (version == "RELEASE_V5.0")
                {
                    Console.WriteLine("[NebulaSpammer] SHA 1 Hash: " + ((string)jss.y) + ", file length: " + ((string)jss.f) + ".");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 8, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_CLOSE_WARNING\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\", \"l\": \"There is a new version available! Join our Discord Server to download it: https://discord.gg/qg6YbDDfFz\", \"j\": \"New version\"}")), ID);
                    return;
                }
                else if (version == "RELEASE_V6.0")
                {
                    Console.WriteLine("[NebulaSpammer] SHA 1 Hash: " + ((string)jss.y) + ", file length: " + ((string)jss.f) + ".");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 8, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_CLOSE_WARNING\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\", \"l\": \"There is a new version available! Join our Discord Server to download it: https://discord.gg/qg6YbDDfFz\", \"j\": \"New version\"}")), ID);
                    return;
                }
                else if (version != "RELEASE_V7.0")
                {
                    Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_13.");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                    Sessions.CloseSession(client.wsSessionId);
                    Program.banHardware(hardwareID);
                    Program.banIP(client.ipAddress);
                    return;
                }

                string SHA1Hash = (string)jss.y;
                string fileLength = (string)jss.f;

                if (SHA1Hash != "A2ADAD7F26ED14B3B45C4C8E7D86C1CA")
                {
                    Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_22.");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                    Sessions.CloseSession(client.wsSessionId);
                    Program.banHardware(hardwareID);
                    Program.banIP(client.ipAddress);
                    return;
                }

                if (fileLength != "1149440")
                {
                    Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_22.");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                    Sessions.CloseSession(client.wsSessionId);
                    Program.banHardware(hardwareID);
                    Program.banIP(client.ipAddress);
                    return;
                }

                if (requestType == 0 && !client.PACKET_PRESENTATION)
                {
                    if (packetType != "PACKET_PRESENTATION")
                    {
                        Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_14.");
                        Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                        Sessions.CloseSession(client.wsSessionId);
                        Program.banHardware(hardwareID);
                        Program.banIP(client.ipAddress);
                        return;
                    }

                    client.hardwareId = hardwareID;
                    client.PACKET_PRESENTATION = true;

                    Console.WriteLine("[NebulaSpammer] Received PACKET_PRESENTATION (0) from hardware ID ('" + hardwareID + "'), session ID ('" + ID + "'). MD5 SHA1 Hash ('" + SHA1Hash + "'), file length ('" + fileLength + "').");

                    string toSend = "{\"t\": 1, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CONFIRM_PRESENTATION\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}";
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt(toSend)), ID);

                    Console.WriteLine("[NebulaSpammer] Sent CONFIRM_PRESENTATION (1) to session: " + ID + ".");
                }
                else if (requestType == 2)
                {
                    Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_15.");
                    Sessions.CloseSession(client.wsSessionId);
                    Program.banHardware(hardwareID);
                    Program.banIP(client.ipAddress);

                    Console.WriteLine("[NebulaSpammer] Received a PACKET_BANME (2) from hardware ID ('" + hardwareID + "'), session ID ('" + ID + "'). Banned for violation detection.");
                }
                else if (requestType == 4 && client.PACKET_PRESENTATION && !client.PACKET_LOGIN)
                {
                    if (packetType != "PACKET_LOGIN")
                    {
                        Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_16.");
                        Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                        Sessions.CloseSession(client.wsSessionId);
                        Program.banHardware(hardwareID);
                        Program.banIP(client.ipAddress);
                        return;
                    }

                    string username = (string)jss.u;
                    string password = (string)jss.n;

                    if (username.Length > 24 || password.Length > 80)
                    {
                        Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_17.");
                        Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                        Sessions.CloseSession(client.wsSessionId);
                        Program.banHardware(hardwareID);
                        Program.banIP(client.ipAddress);
                        return;
                    }

                    Console.WriteLine("[NebulaSpammer] Received PACKET_LOGIN (4) from hardware ID ('" + hardwareID + "'), session ID ('" + ID + "'). Received credentials:");
                    Console.WriteLine("[NebulaSpammer] Login username: " + username + ".");
                    Console.WriteLine("[NebulaSpammer] Login password: " + password + ".");

                    byte loginStatus = Program.CheckCredentials(ServiceType.NebulaSpammer, username, password, client.hardwareId, client.ipAddress);

                    if (loginStatus == 0)
                    {
                        Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 5, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_LOGIN_FAILED\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                        Console.WriteLine("[NebulaSpammer] Sent CLIENT_LOGIN_FAILED (5) to session: " + ID + ".");
                    }
                    else if (loginStatus == 1)
                    {
                        Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_18.");
                        Program.DeleteAccount(ServiceType.NebulaSpammer, username, password, client.hardwareId, client.ipAddress);
                        Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                        Sessions.CloseSession(client.wsSessionId);
                        Program.banHardware(hardwareID);
                        Program.banIP(client.ipAddress);
                        return;
                    }
                    else if (loginStatus == 2)
                    {
                        client.PACKET_LOGIN = true;
                        Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 6, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_LOGIN_SUCCESS\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                        Console.WriteLine("[NebulaSpammer] Sent CLIENT_LOGIN_SUCCESS (6) to session: " + ID + ".");
                    }
                    else
                    {
                        Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_19.");
                        Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                        Sessions.CloseSession(client.wsSessionId);
                        Program.banHardware(hardwareID);
                        Program.banIP(client.ipAddress);
                        return;
                    }
                }
                else
                {
                    Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_20.");
                    Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                    Program.banHardware(hardwareID);
                    Sessions.CloseSession(client.wsSessionId);
                    Program.banIP(client.ipAddress);
                }
            }
            catch
            {
                Console.WriteLine("[NebulaSpammer] Ban reason for session ID '" + ID + "': BAN_REASON_T_21.");
                Sessions.SendTo(System.Text.Encoding.Unicode.GetBytes(Utils.CustomEncrypt("{\"t\": 3, \"r\": " + Utils.GetUniqueLong(13) + ", \"s\": \"" + Utils.GetUniqueKey(27) + "\", \"c\": true, \"p\": \"CLIENT_BAN\", \"m\": \"" + TimestampUtils.GetTimestamp() + "\"}")), ID);
                msg = msg.Replace(" ", "").Replace('\t'.ToString(), "");
                string[] splitted = Strings.Split(msg, "\"h\":");
                string hardware = Strings.Split(splitted[1], "\"")[0];
                Program.banHardware(hardware);
                Sessions.CloseSession(client.wsSessionId);
                Program.banIP(client.ipAddress);
            }
        }
        catch
        {

        }
    }
}