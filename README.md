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


Use it in your code:
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
