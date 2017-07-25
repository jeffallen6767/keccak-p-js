var keccak = require("./index"),
  tester = require("testing"),
  data = {
    "modes": {
      "SHA-3-256": [
      /*
        [
          "", 
          "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        ],
      */
      /*
        [
          "abc", 
          "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        ],
       */
       /*
       [
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".split(" "),
        "...hmmm..."
       ],
       */
       
       [
        "E7 DD E1 40 79 8F 25 F1 8A 47 C0 33 F9 CC D5 84 EE A9 5A A6 1E 26 98 D5 4D 49 80 6F 30 47 15 BD 57 D0 53 62 05 4E 28 8B D4 6F 8E 7F 2D A4 97 FF C4 47 46 A4 A0 E5 FE 90 76 2E 19 D6 0C DA 5B 8C 9C 05 19 1B F7 A6 30 AD 64 FC 8F D0 B7 5A 93 30 35 D6 17 23 3F A9 5A EB 03 21 71 0D 26 E6 A6 A9 5F 55 CF DB 16 7C A5 81 26 C8 47 03 CD 31 B8 43 9F 56 A5 11 1A 2F F2 01 61 AE D9 21 5A 63 E5 05 F2 70 C9 8C F2 FE BE 64 11 66 C4 7B 95 70 36 61 CB 0E D0 4F 55 5A 7C B8 C8 32 CF 1C 8A E8 3E 8C 14 26 3A AE 22 79 0C 94 E4 09 C5 A2 24 F9 41 18 C2 65 04 E7 26 35 F5 16 3B A1 30 7F E9 44 F6 75 49 A2 EC 5C 7B FF F1 EA".split(" "),
        "whatever..."
       ],
       
        /*
        ["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"]
        */
      ]
    }
  },
  modes = data.modes,
  keys = Object.keys(modes),
  tests = {};

//console.log("keccak", keccak);

// make tests
keys.forEach(function(key) {
  var mode = keccak.mode(key),
    todo = modes[key],
    testKey = "sync test keccak.mode(" + key + ")";
  
  tests[testKey] = function(test) {
    todo.forEach(function(pair) {
      test.startTime();
      var result = mode.init().update(pair[0]).digest();
      test.endTime();
      test.assert.identical(result, pair[1]);
    });
    test.done();
  };
});

// run tests
tester.run(tests);

/*
blah = {
    "sync test keccak.modes": function(test) {
      var ;
      modes.forEach(function(key) {
        
        
      });
      
    },

    "async test keccak.hash.sha256()": function(test) {
      data.sha256.forEach(function(pair) {
        test.startTime();
        keccak.hash.sha256(pair[0], function(result) {
          test.endTime();
          test.assert.identical(result, pair[1]);
        });
      });
      test.done();
    }
   
  }
  */