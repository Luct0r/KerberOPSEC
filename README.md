# KerberOPSEC

I came across an article ([Kerberoasting With OPSEC](https://m365internals.com/2021/11/08/kerberoast-with-opsec/)) talking about some of the ways Kerberoasting gets detected and how to potentially avoid making such common mistakes.

Chief among them were LDAP queries that search the entire domain for accounts with an SPN, requesting too many tickets at once, and/or not taking care to look at key user attributes indicating a honeypot account.

So I thought it would be cool to write this in C# to help myself learn some coding and who knows, maybe it will come in handy one day.

# Usage
