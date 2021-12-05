using System;

public static class TimestampUtils
{
    public static long GetUnixTime(DateTime time)
    {
        return ((DateTimeOffset)time).ToUnixTimeSeconds();
    }

    public static DateTime UnixTimeStampToDateTime(double unixTimeStamp)
    {
        return new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unixTimeStamp);
    }

    public static string GetTimestamp(DateTime dateTime)
    {
        string year = dateTime.Year.ToString();
        string month = dateTime.Month.ToString();

        if (month.Length == 1)
        {
            month = "0" + month;
        }

        string day = dateTime.Day.ToString();

        if (day.Length == 1)
        {
            day = "0" + day;
        }

        string hour = dateTime.Hour.ToString();

        if (hour.Length == 1)
        {
            hour = "0" + hour;
        }

        string minute = dateTime.Minute.ToString();

        if (minute.Length == 1)
        {
            minute = "0" + minute;
        }

        return year + "-" + month + "-" + day + "T" + hour + ":" + minute;
    }

    public static string GetTimestamp()
    {
        return GetTimestamp(DateTime.UtcNow);
    }

    public static bool IsTimestampValid(string timestamp)
    {
        DateTime currentTime = DateTime.UtcNow;
        long currentTimeUnix = GetUnixTime(currentTime);

        long currentTimeUnixMinute1 = currentTimeUnix + 60;
        DateTime currentTimeMinute1 = UnixTimeStampToDateTime(currentTimeUnixMinute1);

        long currentTimeUnixMinute2 = currentTimeUnix + 120;
        DateTime currentTimeMinute2 = UnixTimeStampToDateTime(currentTimeUnixMinute2);

        long currentTimeUnixMinute1_1 = currentTimeUnix - 60;
        DateTime currentTimeMinute1_1 = UnixTimeStampToDateTime(currentTimeUnixMinute1_1);

        long currentTimeUnixMinute2_2 = currentTimeUnix - 120;
        DateTime currentTimeMinute2_2 = UnixTimeStampToDateTime(currentTimeUnixMinute2_2);

        if (timestamp == GetTimestamp(currentTime) || timestamp == GetTimestamp(currentTimeMinute1) || timestamp == GetTimestamp(currentTimeMinute2) || timestamp == GetTimestamp(currentTimeMinute1_1) || timestamp == GetTimestamp(currentTimeMinute2_2))
        {
            return true;
        }

        return false;
    }
}