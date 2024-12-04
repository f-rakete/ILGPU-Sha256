namespace LGPU_Sha256
{
    internal class Program
    {
        static void Main(string[] args)
        {
            List<string> strings = new List<string>()
            {
                "Hello there",
                "Things are odd here",
                "I think we should leave"
            };

            Sha256.Setup();

            foreach (string s in strings)
                Sha256.AddJob(s);

            var results = Sha256.CalcJobs();

            foreach(var r in results)
            {
                Console.WriteLine(BitConverter.ToString(r).Replace("-", ""));
            }



        }
    }
}