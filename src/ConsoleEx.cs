namespace portscan
{
    internal static class ConsoleEx
    {
        private static readonly object ConsoleLock = new();

        public static void Write(params object[] objects)
        {
            lock (ConsoleLock)
            {
                foreach (var obj in objects)
                {
                    if (obj is ConsoleColor cc)
                    {
                        Console.ForegroundColor = cc;
                    }
                    else if (obj is byte b &&
                             b == 0x00)
                    {
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.Write(obj);
                    }
                }
            }
        }
    }
}