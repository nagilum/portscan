using System.Net;
using System.Net.Sockets;

namespace portscan
{
    internal static class PortScanner
    {
        private static int Finished { get; set; }

        private static int Total { get; set; }

        private static int Scanned { get; set; }

        private static List<int> OpenPorts { get; } = new();

        private static DateTimeOffset Started { get; set; }

        public static void Init(
            IPAddress ip,
            string hostname,
            int fromPort,
            int toPort,
            int timeoutMilliseconds)
        {
            Started = DateTimeOffset.Now;
            Total = toPort - fromPort;

            ConsoleEx.Write(
                "Scanning ",
                ConsoleColor.Yellow,
                hostname,
                (byte)0x00,
                " (",
                ConsoleColor.Yellow,
                ip,
                (byte)0x00,
                ")",
                Environment.NewLine);

            ConsoleEx.Write(
                "From port ",
                ConsoleColor.Blue,
                fromPort,
                (byte)0x00,
                " to ",
                ConsoleColor.Blue,
                toPort,
                (byte)0x00,
                " with a timeout of ",
                ConsoleColor.Blue,
                timeoutMilliseconds,
                "ms",
                (byte)0x00,
                ".",
                Environment.NewLine,
                Environment.NewLine);

            Parallel.For(
                fromPort,
                toPort + 1,
                port => ScanPort(ip, port, timeoutMilliseconds));
        }

        public static void WriteReport()
        {
            ConsoleEx.Write(
                Environment.NewLine,
                "Open Ports:",
                Environment.NewLine);

            if (OpenPorts.Count == 0)
            {
                ConsoleEx.Write(
                    ConsoleColor.DarkGray,
                    "No ports are open in the given range.",
                    (byte)0x00,
                    Environment.NewLine,
                    Environment.NewLine);

                return;
            }

            foreach (var port in OpenPorts)
            {
                var key = $"{port}/tcp";
                var desc = Program.KnownPorts.ContainsKey(key)
                    ? Program.KnownPorts[key].Description
                    : null;

                ConsoleEx.Write(
                    ConsoleColor.DarkGray,
                    new string('.', 5 - port.ToString().Length),
                    ConsoleColor.Blue,
                    port,
                    (byte)0x00,
                    ": ",
                    desc ?? "Unknown service",
                    Environment.NewLine);
            }

            var ended = DateTimeOffset.Now;
            var duration = ended - Started;

            ConsoleEx.Write(
                Environment.NewLine,
                "Started: ",
                ConsoleColor.Yellow,
                Started,
                (byte)0x00,
                Environment.NewLine,
                "Ended",
                ConsoleColor.DarkGray,
                "..",
                (byte)0x00,
                ": ",
                ConsoleColor.Yellow,
                ended,
                (byte)0x00,
                Environment.NewLine,
                "Took",
                ConsoleColor.DarkGray,
                "...",
                (byte)0x00,
                ": ",
                ConsoleColor.Yellow,
                duration,
                (byte)0x00,
                Environment.NewLine);
        }

        private static void ScanPort(
            IPAddress ip,
            int port,
            int timeoutMilliseconds)
        {
            if (!Program.KeepGoing)
            {
                return;
            }

            ConsoleColor statusColor;
            string status;
            string? desc = null;

            try
            {
                var socket = new Socket(
                    AddressFamily.InterNetwork,
                    SocketType.Stream,
                    ProtocolType.Tcp);

                var result = socket.BeginConnect(ip, port, null, null);
                var failed = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(timeoutMilliseconds), true);

                if (socket.Connected)
                {
                    socket.EndConnect(result);
                }
                else
                {
                    socket.Close();

                    throw new Exception(
                        $"Port {port} is not open.");
                }

                statusColor = ConsoleColor.Green;
                status = "open.";

                OpenPorts.Add(port);

                var key = $"{port}/tcp";

                desc = "Unknown service";

                if (Program.KnownPorts.ContainsKey(key) &&
                    Program.KnownPorts[key].Description is not null)
                {
                    desc = Program.KnownPorts[key].Description;
                }
            }
            catch
            {
                statusColor = ConsoleColor.Red;
                status = "closed.";
            }

            Finished++;

            ConsoleEx.Write(
                ConsoleColor.DarkGray,
                new string('.', 5 - port.ToString().Length),
                ConsoleColor.Blue,
                port,
                (byte)0x00,
                " ",
                statusColor,
                status,
                (byte)0x00,
                " ",
                desc ?? string.Empty,
                Environment.NewLine);

            Scanned++;

            if (Scanned < 50)
            {
                return;
            }

            Scanned = 0;

            var sf = DateTimeOffset.Now - Started;
            var mssf = sf.TotalMilliseconds;
            var pl = Total - Finished;
            var mspp = mssf / Finished;
            var msl = pl * mspp;
            var ts = TimeSpan.FromMilliseconds(msl);

            ConsoleEx.Write(
                (byte)0x00,
                "Scanned approximately ",
                ConsoleColor.Yellow,
                Finished,
                (byte)0x00,
                " of ",
                ConsoleColor.Yellow,
                Total,
                (byte)0x00,
                " ports. Estimated ",
                ConsoleColor.Yellow,
                ts,
                (byte)0x00,
                " left..",
                Environment.NewLine);
        }
    }
}