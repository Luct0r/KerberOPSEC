# KerberOPSEC

I came across an article ([Kerberoasting With OPSEC](https://m365internals.com/2021/11/08/kerberoast-with-opsec/)) talking about some of the ways Kerberoasting gets detected and how to potentially avoid making such common mistakes.

Chief among them were LDAP queries that search the entire domain for accounts with an SPN, requesting too many tickets at once, and/or not taking care to look at key user attributes indicating a honeypot account.

So I thought it would be cool to write this in C# to help myself learn some coding and who knows, maybe it will come in handy one day.

# Usage
```
C:\>KerberOPSEC.exe -h

-GetDN                                  : Retreives current domain Distinguished Name
-ListOUs <DomainDistinguishedName>      : Lists all OUs in the domain
-CheckOU <OUDistinguishedName>          : Checks an OU for sub-OUs, Groups, and Users
-CheckGroup <GroupDistinguishedName>    : Checks a Group for Users
-CheckSPN <UserDistinguishedName>       : Checks an account for an SPN and shows OPSEC info
-GetSPN <UserDistinguishedName> <SPN>   : Retreives hash for specified SPN
```

```
C:\>KerberOPSEC.exe -GetDN

Distinguished Name:

---> DC=contoso,DC=local
```

```
C:\>KerberOPSEC.exe -ListOUs "DC=contoso,DC=local"

OUs:

---> OU=Domain Controllers,DC=contoso,DC=local
---> OU=SERVERS,DC=contoso,DC=local
---> OU=WORKSTATIONS,DC=contoso,DC=local
---> OU=USERS,DC=contoso,DC=local
---> OU=IT,OU=USERS,DC=contoso,DC=local
```

```
C:\>KerberOPSEC.exe -CheckOU "OU=IT,OU=USERS,DC=contoso,DC=local"

OUs:


Groups:

---> CN=Admins,OU=IT,OU=USERS,DC=contoso,DC=local
---> CN=HelpDesk,OU=IT,OU=USERS,DC=contoso,DC=local

Users:

---> CN=SQLUser,OU=IT,OU=USERS,DC=contoso,DC=local
```

```
C:\>KerberOPSEC.exe -CheckGroup "CN=Admins,OU=IT,OU=USERS,DC=contoso,DC=local"

Users:

---> CN=Mark,OU=CORP USERS,DC=contoso,DC=local

C:\>KerberOPSEC.exe -CheckSPN "CN=Mark,OU=USERS,DC=contoso,DC=local"

---> No SPN found for mark@contoso.local

C:\>KerberOPSEC.exe -CheckGroup "CN=HelpDesk,OU=IT,OU=USERS,DC=contoso,DC=local"

Users:

---> CN=Ryan,OU=USERS,DC=contoso,DC=local

C:\>KerberOPSEC.exe -CheckSPN "CN=Ryan,OU=USERS,DC=contoso,DC=local"

---> No SPN found for ryan@contoso.local
```

```
C:\>KerberOPSEC.exe -CheckSPN "CN=SQLUser,OU=IT,OU=USERS,DC=contoso,DC=local"

User Attributes:

---> sAMAccountName                : sqluser
---> Description                   : MSSQL
---> servicePrincipalName          : MSSQLSvc/FileSRV:1433
---> whenCreated                   : 1/8/2021 4:52:54 AM
---> whenChanged                   : 1/10/2022 8:29:36 PM
---> userAccountControl            : 66048
---> msds-SupportedEncryptionTypes : 8
---> pwdLastSet                    : 10/14/2021 9:30:37 PM
---> lastLogon                     : 1/15/2022 12:29:36 PM
```

```
C:\>KerberOPSEC.exe -GetSPN "CN=SQLUser,OU=IT,OU=USERS,DC=contoso,DC=local" "MSSQLSvc/SQLSRV:1433"

$krb5tgs$23$*sqluser$contoso.local$MSSQLSvc/SQLSRV:1433*$9d0795ce5c11fdfd74c31681068e5062$375d95c5fc64900cf57357a7bb05c476f185310e7f74a390f4b1baa40fa0696ea4b19bc43685d1c3cd3f9ef6ff3e56941ed8dcc0a3b08beaf1045e6758b87b35125d2260fab495914c150f862994339b9b4f4afadead7380d942e3a858126dacb7d5098de6496f8c65c2af2e2b2347d4c41b7d95deb3eea43d80c28124849a395821bfd6240a3df6e00bb4ee1cb63c9c6d7696ae1647adc93b5c5f4a4ea0fa12438c41a8d425c50572dbc76993167f171fced8fd9f0acff087e2cc73a02766e8357e729e969e920e030edfa4427431e0f9fd4610ad466b92d558cf571b97144ceac31cdd47a34e04c8111bc093aec4473511f4add918faeb9325b04ece4cd4f646798471ce613e010fa91d9d1afef0f1cd35d13730d204a78f95b9174adfbcf3c897386ba244cda08ff794ae9afea5c0e9df8667f899e803a159f39e9b170b1ee946aca1954a156aabfb336f64c15f25b5178aebf3e8ad2b3ae7c93bab8fc5e73bb939785416891a427999275c54907f4ce3d4e5f0ba3e8a3d58a9b7f258e25694299f82d665e267eb1bf93ca264bfcd83f7ae0df2346ab294fa56bda607ed06e45af81fd72634a325d87b6853f3cc3b88cc3f292bfc34b2d88a1e91a404d9278c1276ea9ea9efb20b52cef6a5c1fe7ca405b7659aabbb842ba780ec0666b96253aaec19e2bba5209b586f87f8f477890dfbd76ed5d29bc4294301f13b326b98acdc33720bbde633e36c82893b7fbe8501bd155a321f421b94f6260f8a593e9e2845e731ae2cedc2d62e4025b7ee4dc4011cacd5cf6d2ef009b49745ebb9a77b0fef9656f2cfbdf4b3fe62eabcc9cd51d681bfb1fd2495ac9b953b13e295841783811d1d836286bd77632783d4594ad82eb0ba71f62768c6f29c5916ec723d57b6f783e94df45238e44ce18494351bb4fdd4e2a87a2fc054a584931d2a4ceab6c81113d0d1e60c5ed793f1e88dce85fabe778ee88935f16ae5e0836437b2e5ec8e77b4be3f6955d91713455a4f1c6bea70e04b5746f21b40ae40b1fe3ee125ae712a6921b31f2fd22a47db6a9a3c06d21a3f553aeddfda5112a7e06069e15f57d577d84860c1dbd342d6a57d8e04c70b8da20a98d801436504e9fdcc462dd632a9d43337bac339ebda53c99768ecd6cb6af67d781fd9c108f31b0d255e43d67c2addf1521974ee896400e76be01c968df0b508b31cc4e234d135787d3f2f6f5b2f6a93093c0e4fd41a764af277c42ff63a4367c9e93f9aa711d516a63d87005afd8c36e10e0b5318415a6625163825a701094a71132b69068e21b89042a5ca6dc7f0767f3f5cb8a26959873a90b0832b822d6ecedfa676337d8f945f749cff07981cd63e75990812ecf667ce0ffedd4cc5f96240df552fa0c8f735755b47a351e4c18c79fa8131176ebad3ab2bf22aeda4b285837c7cc7edb05dc3189549753c08a0287cea42d7bd6e7d20710a29aecaf78abb8f63389a5070609691
```

# References
[Microsoft 365 Security: Kerberoast With OPSEC](https://m365internals.com/2021/11/08/kerberoast-with-opsec/) \
[GhostPack: SharpRoast](https://github.com/GhostPack/SharpRoast) \
[Stack Overflow: Difference between PrincipalSearcher and DirectorySearcher](https://stackoverflow.com/questions/23176284/difference-between-principalsearcher-and-directorysearcher) \
[Stack Overflow: Active Directory : PropertiesToLoad get all properties](https://stackoverflow.com/questions/28214732/active-directory-propertiestoload-get-all-properties) \
[GhostPack: SharpRoast](https://github.com/GhostPack/SharpRoast)
