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
	}
}
