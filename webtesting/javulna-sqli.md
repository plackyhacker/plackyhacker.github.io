[Home](https://plackyhacker.github.io)

# Javulna Auth Bypass and RCE Walkthrough

At the time of writing I am currently studying OSWE and I decided to do a bit of Java [MVC](https://www.tutorialspoint.com/mvc_framework/mvc_framework_introduction.htm) exploitation as part of my studies. The OSWE exam requires the candidate to bypass authentication and gain reverse shell in a single exploit script, so that's what I decided to do using the [Javulna](https://github.com/defdeveu/code.java.Javulna) vulnerable web app.

The OSWE is a source code review exam so I will use the Java code to find the vulnerabilities and exploit them.

The Javulna application is a REST API web application; this means there is no website front end.

## My Methodology

I have developed my own method for exploiting web applications when the objectives are to bypass authentication then gain remote code execution; because this is what is expected in the exam. If the objective was to test for as many vulnerabilities as possible in the application then this methodology would need to be adjusted somewhat.

### Mapping out the web application

The first thing I do is to spend a bit of time mapping out the web application's endpoints; the URIs that I can interact with as a user. Because I have access to the source code and I know that it is an MVC application finding the endpoints is quite easy (but can be time consuming). Essentially we are looking for classes that use the `@RestController` annotation, and the functions within the class that use the `@RequestMapping`, `@PostMapping`, `@PutMapping`, `@GettMapping` etc.

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

### Looking for Vulnerabilities

coming soon

## Vulnerability 1

coming soon

## Vulnerability 2

coming soon

## Walkthrough

coming soon

## Full Exploit Code

coming soon

[Home](https://plackyhacker.github.io)
