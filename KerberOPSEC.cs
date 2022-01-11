using System;
using System.Text.RegularExpressions;
using System.Security.Principal;
using System.Collections.Generic;

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
		public static void QueryLDAP(string tLDAP, string tQry)
		{
			try
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
			catch (Exception)
			{
				Console.WriteLine("Check arguments and quotes...");
			}
		}
	}
}
