## keccak-p-js

A sha-3 winner Keccak-p implementation in JavaScript


## Getting the Code

To get a local copy of the current code, clone it using git:

    $ git clone git://github.com/jeffallen6767/keccak-p-js.git
    $ cd keccak-p-js


If everything worked out, install all dependencies:

    $ npm install


Run the tests:

    $ npm run tests


Use it in you own project:

    $ npm install git://github.com/jeffallen6767/keccak-p-js.git --save
    
    or
    
    $ npm install https://github.com/jeffallen6767/keccak-p-js.git --save


Use it in your code ( see test.js for in-depth examples and details ):
```javascript
var keccak = require("keccak-p-js");

// sync example:
var hash = keccak.mode("SHA-3-256").init().update("abc").digest();
console.log("sync SHA-3-256 of abc is ", hash);

// async example:
keccak.mode("SHA-3-256", function(mode) {
  mode.init(function(input) {
    input.update("abc", function(output) {
      output.digest(function(hash) {
        console.log("async SHA-3-256 of abc is ", hash);
      });
    });
  });
});
```

Supports the following modes:

    SHA-3-224
    SHA-3-256
    SHA-3-384
    SHA-3-512
    
    and
    
    SHAKE-128
    SHAKE-256


How to SHAKE-n:
just create an instance with a shake mode, and update it with input as normal
then call instance.digest(n-bytes) as many times as you like to create n bytes of hash 
at whatever rate you need
```javascript

var shake = keccak.mode("SHAKE-256").init().update("abc"),
  hash = [
    shake.digest(32),
    shake.digest(16),
    shake.digest(8),
    shake.digest(5),
    shake.digest(3)
  ].join("");

console.log("sync 64 bytes of SHAKE-256 of abc is ", hash);
```