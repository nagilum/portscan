using System.Net;
using System.Text.Json;

namespace portscan
{
    internal static class Program
    {
        public static Dictionary<string, PortEntry> KnownPorts { get; set; } = new();

        public static bool KeepGoing { get; set; } = true;

        private static void Main(string[] args)
        {
            Console.ResetColor();

            if (!ParseCmdArgs(
                args,
                out var target,
                out var fromPort,
                out var toPort,
                out var timeoutMilliseconds))
            {
                return;
            }

            if (target is null)
            {
                ShowAppUsage();
                return;
            }

            if (!ParseTargetToIp(
                target,
                out var ip) ||
                ip is null)
            {
                return;
            }

            LoadPortsJson();

            Console.CancelKeyPress += (s, e) =>
            {
                ConsoleEx.Write(
                    Environment.NewLine,
                    ConsoleColor.Magenta,
                    "Aborted by user! Cleaning up some threads..",
                    (byte)0x00,
                    Environment.NewLine,
                    Environment.NewLine);

                KeepGoing = false;
                e.Cancel = true;
            };

            PortScanner.Init(
                ip,
                target,
                fromPort,
                toPort,
                timeoutMilliseconds);

            PortScanner.WriteReport();
        }

        private static void LoadPortsJson()
        {
            var path = Path.Combine(
                Directory.GetCurrentDirectory(),
                "ports.json");

            if (!File.Exists(path))
            {
                return;
            }

            try
            {
                var json = File.ReadAllText(path);
                var dict = JsonSerializer.Deserialize<Dictionary<string, PortEntry>>(json);

                if (dict is null)
                {
                    return;
                }

                KnownPorts = dict;
            }
            catch
            {
                //
            }
        }

        private static bool ParseCmdArgs(
            string[] args,
            out string? target,
            out int fromPort,
            out int toPort,
            out int timeoutMilliseconds)
        {
            target = null;
            fromPort = 1;
            toPort = 65535;
            timeoutMilliseconds = 1000;

            var skip = false;

            for (var i = 0; i < args.Length; i++)
            {
                if (skip)
                {
                    skip = false;
                    continue;
                }

                switch (args[i])
                {
                    case "-t":
                        if (i == args.Length - 1)
                        {
                            ConsoleEx.Write(
                                "The param ",
                                ConsoleColor.Blue,
                                "-t ",
                                (byte)0x00,
                                "must be followed by a valid number of 1 or above.",
                                Environment.NewLine);

                            return false;
                        }

                        if (!int.TryParse(args[i + 1], out timeoutMilliseconds) ||
                            timeoutMilliseconds < 1)
                        {
                            ConsoleEx.Write(
                                "Could not parse ",
                                ConsoleColor.Red,
                                args[i + 1],
                                (byte)0x00,
                                " to a valid timeout in milliseconds.",
                                Environment.NewLine);

                            return false;
                        }

                        skip = true;
                        break;

                    case "-fp":
                        if (i == args.Length - 1)
                        {
                            ConsoleEx.Write(
                                "The param ",
                                ConsoleColor.Blue,
                                "-fp ",
                                (byte)0x00,
                                "must be followed by a valid number between (and including) 1 and 65535.",
                                Environment.NewLine);

                            return false;
                        }

                        if (!int.TryParse(args[i + 1], out fromPort) ||
                            fromPort < 1 ||
                            fromPort > 65535)
                        {
                            ConsoleEx.Write(
                                "Could not parse ",
                                ConsoleColor.Red,
                                args[i + 1],
                                (byte)0x00,
                                " to a valid port number.",
                                Environment.NewLine);

                            return false;
                        }

                        skip = true;
                        break;

                    case "-tp":
                        if (i == args.Length - 1)
                        {
                            ConsoleEx.Write(
                                "The param ",
                                ConsoleColor.Blue,
                                "-tp ",
                                (byte)0x00,
                                "must be followed by a valid number between (and including) 1 and 65535.",
                                Environment.NewLine);

                            return false;
                        }

                        if (!int.TryParse(args[i + 1], out toPort) ||
                            toPort < 1 ||
                            toPort > 65535)
                        {
                            ConsoleEx.Write(
                                "Could not parse ",
                                ConsoleColor.Red,
                                args[i + 1],
                                (byte)0x00,
                                " to a valid port number.",
                                Environment.NewLine);

                            return false;
                        }

                        skip = true;
                        break;

                    default:
                        if (target is not null)
                        {
                            ConsoleEx.Write(
                                "A target has already been set to ",
                                ConsoleColor.Red,
                                target,
                                (byte)0x00,
                                Environment.NewLine);

                            return false;
                        }

                        target = args[i];
                        break;
                }
            }

            if (toPort < fromPort)
            {
                ConsoleEx.Write(
                    ConsoleColor.Blue,
                    "-fp ",
                    (byte)0x00,
                    "cannot be higher than ",
                    ConsoleColor.Blue,
                    "-tp",
                    (byte)0x00,
                    Environment.NewLine);

                return false;
            }

            return true;
        }

        private static bool ParseTargetToIp(
            string target,
            out IPAddress? ip)
        {
            ip = null;

            try
            {
                ip = Dns.GetHostAddresses(target)
                    .FirstOrDefault(n => n.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            }
            catch (Exception ex)
            {
                ConsoleEx.Write(
                    "Error while parsing target ",
                    ConsoleColor.Yellow,
                    target,
                    (byte)0x00,
                    " to valid IP address.",
                    Environment.NewLine,
                    ex.Message,
                    Environment.NewLine,
                    Environment.NewLine);
            }

            return ip is not null;
        }

        private static void ShowAppUsage()
        {
            ConsoleEx.Write(
                "PortScan v0.1-alpha",
                Environment.NewLine,
                Environment.NewLine);

            ConsoleEx.Write(
                "Usage:",
                Environment.NewLine,
                "  portscan ",
                ConsoleColor.Blue,
                "[<options>] ",
                ConsoleColor.Yellow,
                "target",
                (byte)0x00,
                Environment.NewLine,
                Environment.NewLine);

            ConsoleEx.Write(
                "Options:",
                Environment.NewLine,
                "  -fp ",
                ConsoleColor.Blue,
                "port-number  ",
                (byte)0x00,
                "Set the port number to scan from. Defaults to 1.",
                Environment.NewLine,
                "  -tp ",
                ConsoleColor.Blue,
                "port-number  ",
                (byte)0x00,
                "Set the port number to scan to. Defaults to 65535.",
                Environment.NewLine,
                "  -t ",
                ConsoleColor.Blue,
                "milliseconds  ",
                (byte)0x00,
                "Timeout for each connection in milliseconds. Defaults to 1000.",
                Environment.NewLine,
                Environment.NewLine);
        }
    }
}