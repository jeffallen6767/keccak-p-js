// test keccak modes
var keccak = require("./index"),
  tester = require("testing"),
  data = {
    "modes": {
      "SHA-3-224":[
      
      ],
      "SHA-3-256": [
        [ // empty msg
          "", 
          "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        ],
        [ // short msg
          "abc", 
          "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        ],
        [
          [ // array of decimal
            159, 47, 204, 124, 144, 222, 9, 13, 107, 135, 205, 126, 151, 24, 193, 234,
            108, 178, 17, 24, 252, 45, 93, 233, 249, 126, 93, 182, 172, 30, 156, 16
          ],
          "2f1a5f7159e34ea19cddc70ebf9b81f1a66db40615d7ead3cc1f1b954d82a3af"
        ],
        [
          [ // array of octal
            0237, 057, 0314, 0174, 0220, 0336, 011, 015, 0153, 0207, 0315, 0176, 0227, 030, 0301, 0352,
            0154, 0262, 021, 030, 0374, 055, 0135, 0351, 0371, 0176, 0135, 0266, 0254, 036, 0234, 020
          ],
          "2f1a5f7159e34ea19cddc70ebf9b81f1a66db40615d7ead3cc1f1b954d82a3af"
        ],
        [
          [ // array of hex
            0x9F, 0x2F, 0xCC, 0x7C, 0x90, 0xDE, 0x09, 0x0D, 0x6B, 0x87, 0xCD, 0x7E, 0x97, 0x18, 0xC1, 0xEA,
            0x6C, 0xB2, 0x11, 0x18, 0xFC, 0x2D, 0x5D, 0xE9, 0xF9, 0x7E, 0x5D, 0xB6, 0xAC, 0x1E, 0x9C, 0x10
          ],
          "2f1a5f7159e34ea19cddc70ebf9b81f1a66db40615d7ead3cc1f1b954d82a3af"
        ],
        [
          [ // array of decimal
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
          ],
          "2b43036c229ba512995f91fdb46fcd5327a4dc834d86d6e0f58a08053346dc2e"
        ],
        [
          [ // array of string hex 
            "E7", "DD", "E1", "40", "79", "8F", "25", "F1", "8A", "47", "C0", "33", "F9", "CC", "D5", "84",
            "EE", "A9", "5A", "A6", "1E", "26", "98", "D5", "4D", "49", "80", "6F", "30", "47", "15", "BD",
            "57", "D0", "53", "62", "05", "4E", "28", "8B", "D4", "6F", "8E", "7F", "2D", "A4", "97", "FF",
            "C4", "47", "46", "A4", "A0", "E5", "FE", "90", "76", "2E", "19", "D6", "0C", "DA", "5B", "8C",
            "9C", "05", "19", "1B", "F7", "A6", "30", "AD", "64", "FC", "8F", "D0", "B7", "5A", "93", "30",
            "35", "D6", "17", "23", "3F", "A9", "5A", "EB", "03", "21", "71", "0D", "26", "E6", "A6", "A9",
            "5F", "55", "CF", "DB", "16", "7C", "A5", "81", "26", "C8", "47", "03", "CD", "31", "B8", "43",
            "9F", "56", "A5", "11", "1A", "2F", "F2", "01", "61", "AE", "D9", "21", "5A", "63", "E5", "05",
            "F2", "70", "C9", "8C", "F2", "FE", "BE", "64", "11", "66", "C4", "7B", "95", "70", "36", "61",
            "CB", "0E", "D0", "4F", "55", "5A", "7C", "B8", "C8", "32", "CF", "1C", "8A", "E8", "3E", "8C",
            "14", "26", "3A", "AE", "22", "79", "0C", "94", "E4", "09", "C5", "A2", "24", "F9", "41", "18",
            "C2", "65", "04", "E7", "26", "35", "F5", "16", "3B", "A1", "30", "7F", "E9", "44", "F6", "75",
            "49", "A2", "EC", "5C", "7B", "FF", "F1", "EA"
          ],
          "aa45fbc5788aacbcb5aecb8ac032a90baf1d7d4cb509e9b9960b601c1b9eaefe"
        ]
      ],
      "SHA-3-384":[], 
      "SHA-3-512":[],
      "SHAKE-128":[],
      "SHAKE-256":[]
    }
  },
  modes = data.modes,
  keys = Object.keys(modes),
  tests = {};

//console.log("keccak", keccak);

// make tests
keys.forEach(function(key) {
  var
    todo = modes[key],
    syncKey = "sync test keccak.mode(" + key + ")",
    asyncKey = "async test keccak.mode(" + key + ")";
  
  tests[syncKey] = function(test) {
    todo.forEach(function(pair) {
      test.startTime();
      var result = keccak.mode(key).init().update(pair[0]).digest();
      test.endTime();
      test.assert.identical(result, pair[1]);
    });
    test.done();
  };
  tests[asyncKey] = function(test) {
    var num = todo.length,
      done = 0;
    if (num) {
      todo.forEach(function(pair) {
        test.startTime();
        keccak.mode(key, function(instance) {
          instance.init(function(instance) {
            instance.update(pair[0], function(instance) {
              instance.digest(function(result) {
                test.endTime();
                test.assert.identical(result, pair[1]);
                if (++done === num) {
                  test.done();
                }
              });
            });
          });
        })
      });
    } else {
      test.done();
    }
  };
});

// run tests
tester.run(tests);
