using System;

public class MainClass
{
    public static void Main(string[] args)
    {
        Console.WriteLine("Congrats, the stub loading method worked!");
        Console.WriteLine("These are the args that you passed, since most .net apps need them!");
        for(int i = 0; i < args.Length; i++ )
        {
            Console.WriteLine("Arg number {0} is {1}", i, args[i]);
        }
    }
}
