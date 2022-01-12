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
                    Console.WriteLine();
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
                    Console.WriteLine();
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
                Console.WriteLine();
            }
            catch (Exception)
            {
                Console.WriteLine("Check arguments and quotes?");
                return;
            }
        }
        public static void QueryLDAPUser(string tLDAP)
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
                    Filter = "(sAMAccountName=" + user + ")"
                };

                SearchResult sResult = subSearcher.FindOne();
                ResultPropertyCollection pCollection = sResult.Properties;
                ICollection iCollection = pCollection.PropertyNames;
                IEnumerator iEnumerator = iCollection.GetEnumerator();

                string[] strArray = new string[9];
                while (iEnumerator.MoveNext())
                {
                    if (iEnumerator.Current.ToString() == "samaccountname")
                    {
                        strArray.SetValue("---> sAMAccountName                : " + sResult.Properties[iEnumerator.Current.ToString()][0], 0);
                    }
                    if (iEnumerator.Current.ToString() == "description")
                    {
                        strArray.SetValue("---> Description                   : " + sResult.Properties[iEnumerator.Current.ToString()][0], 1);
                    }
                    if (iEnumerator.Current.ToString() == "serviceprincipalname")
                    {
                        strArray.SetValue("---> servicePrincipalName          : " + sResult.Properties[iEnumerator.Current.ToString()][0], 2);
                    }
                    if (iEnumerator.Current.ToString() == "whencreated")
                    {
                        strArray.SetValue("---> whenCreated                   : " + sResult.Properties[iEnumerator.Current.ToString()][0], 3);
                    }
                    if (iEnumerator.Current.ToString() == "whenchanged")
                    {
                        strArray.SetValue("---> whenChanged                   : " + sResult.Properties[iEnumerator.Current.ToString()][0], 4);
                    }
                    if (iEnumerator.Current.ToString() == "useraccountcontrol")
                    {
                        strArray.SetValue("---> userAccountControl            : " + sResult.Properties[iEnumerator.Current.ToString()][0], 5);
                    }
                    if (iEnumerator.Current.ToString() == "msds-supportedencryptiontypes")
                    {
                        strArray.SetValue("---> msds-SupportedEncryptionTypes : " + sResult.Properties[iEnumerator.Current.ToString()][0], 6);
                    }
                    if (iEnumerator.Current.ToString() == "pwdlastset")
                    {
                        long pwdSet = (long)sResult.Properties[iEnumerator.Current.ToString()][0];
                        DateTime dtPwdSet = DateTime.FromFileTime(pwdSet);
                        strArray.SetValue("---> pwdLastSet                    : " + dtPwdSet, 7);
                    }
                    if (iEnumerator.Current.ToString() == "lastlogon")
                    {
                        long LastLogon = (long)sResult.Properties[iEnumerator.Current.ToString()][0];
                        DateTime dtLastLogon = DateTime.FromFileTime(LastLogon);
                        strArray.SetValue("---> lastLogon                     : " + dtLastLogon, 8);
                    }
                }

                Console.WriteLine("User Attributes:");
                Console.WriteLine();
                foreach (string str in strArray)
                {
                    Console.WriteLine(str.ToString());
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return;
            }

        }
        public static void CheckSPN(string tLDAP)
        {
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
                    Filter = "(sAMAccountName=" + user + ")"
                };

                SearchResult sResult = subSearcher.FindOne();
                StringBuilder strBuild = new StringBuilder();
                ResultPropertyCollection pCollection = sResult.Properties;
                ICollection iCollection = pCollection.PropertyNames;
                IEnumerator iEnumerator = iCollection.GetEnumerator();
                while (iEnumerator.MoveNext())
                {
                    if (iEnumerator.Current.ToString() == "serviceprincipalname")
                    {
                        strBuild.Append(sResult.Properties[iEnumerator.Current.ToString()][0]);
                    }
                }

                if (strBuild.Length != 0)
                {
                    QueryLDAPUser(tLDAP);
                }
                else
                {
                    Match dnMatch = Regex.Match(tLDAP, "(?<Domain>DC=.*)", RegexOptions.IgnoreCase);
                    string domainDN = dnMatch.Groups["Domain"].ToString();
                    string domain = domainDN.Replace("DC=", "").Replace(',', '.');
                    Console.WriteLine("---> No SPN found for {0}@{1}", user, domain);
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

                Console.WriteLine("Groups:\r\n");
                QueryLDAP(targetLDAP, searchGroup, option);

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
                Kerberoast.Roast.GetDomainSPNTicket(targetLDAP, targetSPN);
            }
        }
    }
}
