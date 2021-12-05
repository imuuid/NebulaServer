public class Client
{
    public string wsSessionId, hardwareId, ipAddress;
    public bool PACKET_PRESENTATION, PACKET_LOGIN, CAN_DO = true;
    public int packets = 0;

    public Client(string wsSessionId, string ipAddress)
    {
        this.wsSessionId = wsSessionId;
        this.ipAddress = ipAddress;
    }
}