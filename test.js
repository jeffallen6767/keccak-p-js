// test keccak modes
var keccak = require("./index"),
  tester = require("testing"),
  str = function() {
    // join all args into one string
    return [].slice.call(arguments).join("");
  },
  bytes = function() {
    // join all args into one string then split into 2 char chunks
    return [].slice.call(arguments).join("").match(/.{1,2}/g);
  },
  testData = {
    "empty message": {
      "input": "",
      "output": {
        "SHA-3-224": "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
        "SHA-3-256": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "SHA-3-384": str(
          "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a",
          "c3713831264adb47fb6bd1e058d5f004"
        ),
        "SHA-3-512": str(
          "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6",
          "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        ),
        "SHAKE-128": "43e41b45a653f2a5c4492c1add544512dda2529833462b71a41a45be97290b6f",
        "SHAKE-256": "ab0bae316339894304e35877b0c28a9b1fd166c796b9cc258a064a8f57e27f2a"
      }
    },
    "short message": {
      "input": "abc",
      "output": {
        "SHA-3-224": "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
        "SHA-3-256": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        "SHA-3-384": str(
          "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2",
          "98d88cea927ac7f539f1edf228376d25"
        ),
        "SHA-3-512": str(
          "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e",
          "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        ),
        "SHAKE-128": "7085901803ec6f17f0ec650a292198275211a56bf13f0bf7241268b50d3f1ec8",
        "SHAKE-256": "9440b99d6088e20203aebafa8e9dffa94ed35ef1f41f5fdf549fbcc5a0f68298"
      }
    },
    "short message bytes": {
      "input": bytes("9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10"),
      "output": {
        "SHA-3-224": "887921848ad98458f3db3e0ecd5ad5db1f0bf9f2d0ca08601074d597",
        "SHA-3-256": "2f1a5f7159e34ea19cddc70ebf9b81f1a66db40615d7ead3cc1f1b954d82a3af",
        "SHA-3-384": str(
          "baae7aaed4fbf42f9316c7e8f722eeb06a598b509f184b22fbd5a81c93d95fff",
          "711f5de90847b3248b6df76cabce07ee"
        ),
        "SHA-3-512": str(
          "b087c90421aebf87911647de9d465cbda166b672ec47ccd4054a7135a1ef885e",
          "7903b52c3f2c3fe722b1c169297a91b82428956a02c631a2240f12162c7bc726"
        ),
        "SHAKE-128": "81ab314a524fc745090162d2ac723c4326e0f9e16fbdba2b1e9914bbeedff96b",
        "SHAKE-256": "9d6307973ed19b270247867e5861172467821a22872e52657ba2ffddf6052025"
      }
    },
    "array of decimal": {
      "input": [
        159, 47, 204, 124, 144, 222, 9, 13, 107, 135, 205, 126, 151, 24, 193, 234,
        108, 178, 17, 24, 252, 45, 93, 233, 249, 126, 93, 182, 172, 30, 156, 16
      ],
      "output": {
        "SHA-3-224": "887921848ad98458f3db3e0ecd5ad5db1f0bf9f2d0ca08601074d597",
        "SHA-3-256": "2f1a5f7159e34ea19cddc70ebf9b81f1a66db40615d7ead3cc1f1b954d82a3af",
        "SHA-3-384": str(
          "baae7aaed4fbf42f9316c7e8f722eeb06a598b509f184b22fbd5a81c93d95fff",
          "711f5de90847b3248b6df76cabce07ee"
        ),
        "SHA-3-512": str(
          "b087c90421aebf87911647de9d465cbda166b672ec47ccd4054a7135a1ef885e",
          "7903b52c3f2c3fe722b1c169297a91b82428956a02c631a2240f12162c7bc726"
        ),
        "SHAKE-128": "81ab314a524fc745090162d2ac723c4326e0f9e16fbdba2b1e9914bbeedff96b",
        "SHAKE-256": "9d6307973ed19b270247867e5861172467821a22872e52657ba2ffddf6052025"
      }
    },
    "array of octal": {
      "input": [
        0237, 057, 0314, 0174, 0220, 0336, 011, 015, 0153, 0207, 0315, 0176, 0227, 030, 0301, 0352,
        0154, 0262, 021, 030, 0374, 055, 0135, 0351, 0371, 0176, 0135, 0266, 0254, 036, 0234, 020
      ],
      "output": {
        "SHA-3-224": "887921848ad98458f3db3e0ecd5ad5db1f0bf9f2d0ca08601074d597",
        "SHA-3-256": "2f1a5f7159e34ea19cddc70ebf9b81f1a66db40615d7ead3cc1f1b954d82a3af",
        "SHA-3-384": str(
          "baae7aaed4fbf42f9316c7e8f722eeb06a598b509f184b22fbd5a81c93d95fff",
          "711f5de90847b3248b6df76cabce07ee"
        ),
        "SHA-3-512": str(
          "b087c90421aebf87911647de9d465cbda166b672ec47ccd4054a7135a1ef885e",
          "7903b52c3f2c3fe722b1c169297a91b82428956a02c631a2240f12162c7bc726"
        ),
        "SHAKE-128": "81ab314a524fc745090162d2ac723c4326e0f9e16fbdba2b1e9914bbeedff96b",
        "SHAKE-256": "9d6307973ed19b270247867e5861172467821a22872e52657ba2ffddf6052025"
      }
    },
    "array of hex": {
      "input": [
        0x9F, 0x2F, 0xCC, 0x7C, 0x90, 0xDE, 0x09, 0x0D, 0x6B, 0x87, 0xCD, 0x7E, 0x97, 0x18, 0xC1, 0xEA,
        0x6C, 0xB2, 0x11, 0x18, 0xFC, 0x2D, 0x5D, 0xE9, 0xF9, 0x7E, 0x5D, 0xB6, 0xAC, 0x1E, 0x9C, 0x10
      ],
      "output": {
        "SHA-3-224": "887921848ad98458f3db3e0ecd5ad5db1f0bf9f2d0ca08601074d597",
        "SHA-3-256": "2f1a5f7159e34ea19cddc70ebf9b81f1a66db40615d7ead3cc1f1b954d82a3af",
        "SHA-3-384": str(
          "baae7aaed4fbf42f9316c7e8f722eeb06a598b509f184b22fbd5a81c93d95fff",
          "711f5de90847b3248b6df76cabce07ee"
        ),
        "SHA-3-512": str(
          "b087c90421aebf87911647de9d465cbda166b672ec47ccd4054a7135a1ef885e",
          "7903b52c3f2c3fe722b1c169297a91b82428956a02c631a2240f12162c7bc726"
        ),
        "SHAKE-128": "81ab314a524fc745090162d2ac723c4326e0f9e16fbdba2b1e9914bbeedff96b",
        "SHAKE-256": "9d6307973ed19b270247867e5861172467821a22872e52657ba2ffddf6052025"
      }
    },
    "multi-block array of zeros": {
      "input": [
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
      "output": {
        "SHA-3-224": "c183b88a86c9c2d9d71f44d96983ec428d0fb59f923e337d8b339e0f",
        "SHA-3-256": "2b43036c229ba512995f91fdb46fcd5327a4dc834d86d6e0f58a08053346dc2e",
        "SHA-3-384": str(
          "d594703d816a1aeb814436c53ec54d7100c5edfb4f806a253fbf6b052864d100",
          "0b5a1a66a066b5d680bfae9ac3e5bcf6"
        ),
        "SHA-3-512": str(
          "fee1198b89e041af5a26a217e4217a66c628c78d11c1fbb482b3643153f3cf0c",
          "04ae421c7e530e19584a494c1f3bd4713ca169a98b937ddf0b9d4d09fadecde9"
        ),
        "SHAKE-128": "9d8fc11caae22ddb535db0aef3cb3ac1594fe634b2b166e8eaee591bd98ba81f",
        "SHAKE-256": "d2fed140e71dde696f84aaf4d6cedea28e83ecb1b7e6987f2030efd7ea0637db"
      }
    },
    "multi-block array of string hex bytes": {
      "input": [
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
      "output": {
        "SHA-3-224": "8aeae10bbea44c613b2b6d65b0b622291e465c9b123c157ec862212d",
        "SHA-3-256": "aa45fbc5788aacbcb5aecb8ac032a90baf1d7d4cb509e9b9960b601c1b9eaefe",
        "SHA-3-384": str(
          "db603423313323b949395b2846f7d3334fbfae32b3efc9e110aa4e634979618a",
          "a64714b90c48ad9d07cec9e76bbaf462"
        ),
        "SHA-3-512": str(
          "969772f6836db4fc32df06647b6234adaa797c303b5accbc2ca0ceb6e3664be1",
          "722696a8dc172cef021b291cb86565c6b8b6399c08fb4c98218c7e5a337e21bf"
        ),
        "SHAKE-128": "6120e174ffc0c538bbd46ea00e620b1d52d6475cf24a01baee2a15dae27c914b",
        "SHAKE-256": "d6f2853b3743687b9bbd05e3f32d6cbecb3f69bd252dfca665865dfb4d2a5eb3"
      }
    },
    "exact block size": {
      "input": bytes(
        "E35780EB9799AD4C77535D4DDB683CF33EF367715327CF4C4A58ED9CBDCDD486",
        "F669F80189D549A9364FA82A51A52654EC721BB3AAB95DCEB4A86A6AFA93826D",
        "B923517E928F33E3FBA850D45660EF83B9876ACCAFA2A9987A254B137C6E140A",
        "21691E1069413848"
      ),
      "output": {
        "SHA-3-224": "5c0c2df13a1fd6762b6e50fb3e080e649c3a7a8dda415c42fb637136",
        "SHA-3-256": "e360b424a5c06704d148352e04f4651f8d3b385c01f24fda09d266d4ed7ff662",
        "SHA-3-384": str(
          "d1c0fa85c8d183beff99ad9d752b263e286b477f79f0710b0103170173978133",
          "44b99daf3bb7b1bc5e8d722bac85943a"
        ),
        "SHA-3-512": str(
          "ff6a7d0efea45e5f0abcb173fce2be76b52d0f3fc363afe31d219472742d73e5",
          "6cee2ab91a94d41335c4fa25cbdd6ebd1a087637caa25099d5a9d60693cf62b9"
        ),
        "SHAKE-128": "786a2410d58ce5ef6e8446ee49ccd2a50557d32fd1e9e0954a4373545da250cc",
        "SHAKE-256": "248606ab062799988e6b0d71c2dbf907e211c963a3823332d6abf4450d311080"
      }
    },
    "large msg array of byte": {
      "input": bytes(
        "3A3A819C48EFDE2AD914FBF00E18AB6BC4F14513AB27D0C178A188B61431E7F5",
        "623CB66B23346775D386B50E982C493ADBBFC54B9A3CD383382336A1A0B2150A",
        "15358F336D03AE18F666C7573D55C4FD181C29E6CCFDE63EA35F0ADF5885CFC0",
        "A3D84A2B2E4DD24496DB789E663170CEF74798AA1BBCD4574EA0BBA40489D764",
        "B2F83AADC66B148B4A0CD95246C127D5871C4F11418690A5DDF01246A0C80A43",
        "C70088B6183639DCFDA4125BD113A8F49EE23ED306FAAC576C3FB0C1E256671D",
        "817FC2534A52F5B439F72E424DE376F4C565CCA82307DD9EF76DA5B7C4EB7E08",
        "5172E328807C02D011FFBF33785378D79DC266F6A5BE6BB0E4A92ECEEBAEB1"
      ),
      "output": {
        "SHA-3-224": "94689ea9f347dda8dd798a858605868743c6bd03a6a65c6085d52bed",
        "SHA-3-256": "c11f3522a8fb7b3532d80b6d40023a92b489addad93bf5d64b23f35e9663521c",
        "SHA-3-384": str(
          "128dc611762be9b135b3739484cfaadca7481d68514f3dfd6f5d78bb1863ae68",
          "130835cdc7061a7ed964b32f1db75ee1"
        ),
        "SHA-3-512": str(
          "6e8b8bd195bdd560689af2348bdc74ab7cd05ed8b9a57711e9be71e9726fda45",
          "91fee12205edacaf82ffbbaf16dff9e702a708862080166c2ff6ba379bc7ffc2"
        ),
        "SHAKE-128": "b867b1c591307a9015112b567ff6b4f318114111fc95e5bd7c9c60b74c1f8725",
        "SHAKE-256": "096f2edb221db42843d65327861282dc946a0ba01a11863ab2d1dfd16e3973d4"
      }
    }
  },
  testKeys = Object.keys(testData),
  tests = {};

// make tests
testKeys.forEach(function(testKey) {
  var
    testType = testData[testKey],
    testInput = testType.input,
    testOutput = testType.output,
    testModes = Object.keys(testOutput),
    shakeBytes = 32,
    shakeMax = 512;
  
  testModes.forEach(function(testMode) {
    var expected = testOutput[testMode],
      isShake = testMode.split("-")[0] === "SHAKE";
    tests["sync test keccak.mode(" + testMode + ") for " + testKey] = function(test) {
      var instance, result, i;
      test.startTime();
      instance = keccak.mode(testMode).init().update(testInput);
      if (isShake) {
        for (i=0; i<shakeMax; i+= shakeBytes) {
          result = instance.digest(shakeBytes);
        }
      } else {
        result = instance.digest();
      }
      test.endTime();
      test.assert.identical(result, expected);
      test.done();
    };
    tests["async test keccak.mode(" + testMode + ") for " + testKey] = function(test) {
      test.startTime();
      keccak.mode(testMode, function(instance) {
        instance.init(function(instance) {
          instance.update(testInput, function(instance) {
            var i, next, last;
            if (isShake) {
              last = shakeMax - shakeBytes;
              next = function(result) {
                if (i === last) {
                  test.endTime();
                  test.assert.identical(result, expected);
                  test.done();
                } else {
                  i+= shakeBytes;
                  instance.digest(shakeBytes, next);
                }
              };
              i = 0;
              instance.digest(shakeBytes, next);
            } else {
              instance.digest(function(result) {
                test.endTime();
                test.assert.identical(result, expected);
                test.done();
              });
            }
          });
        });
      });
    };
  });
});

// run tests
tester.run(tests);
