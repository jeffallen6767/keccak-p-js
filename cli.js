#!/usr/bin/env node
var
  keccak = require("./index"),
  colors = require("colors"),
  fs = require('fs'),
  utf8 = require('utf8'),
  program = require('commander'),
  pkg = require('./package.json'),
  version = pkg.version,
  KECCAK_MODES = {
    "sha": [
      "sha224", "sha256", "sha384", "sha512"
    ],
    "shake": [
      "shake128", "shake256"
    ]
  },
  kSha = KECCAK_MODES.sha,
  kShake = KECCAK_MODES.shake,
  make_red = function make_red(txt) {
    return colors.red(txt);
  },
  message,
  filePath,
  compare,
  kInst,
  result,
  done;

  
program
  .version(version)
  .option('-a, --algorithm [algo]', 'algorithm to apply keccak')
  .option('-m, --message [text]', 'text to apply keccak')
  .option('-f, --file [path]', 'file to apply keccak')
  .option('-c, --compare [checksum]', 'Checksum to compare with result')
  .parse(process.argv);

algo = program.algorithm;
message = program.message;
filePath = program.file;
compare = program.compare;

done = function(result) {
  if (compare) {
    if (compare.toLowerCase() === result.toLowerCase()) {
      console.log(
        colors.green.bold(result)
      );
      process.exit(0);
    } else {
      console.log(
        colors.red.bold(result)
      );
      process.exit(1);
    }
  } else {
    console.log(
      colors.white.bold(result)
    );
    process.exit(0);
  }
};

if (algo && kSha.indexOf(algo) !== -1) {
  algo = algo.replace("sha", "SHA-3-");
  console.log("algo", algo);
/* TODO SHAKE
} else if (algo && kShake.indexOf(algo) !== -1) {

*/
} else {
  console.log(
    colors.white.bold('ERROR: Must use with -a [algo]')
  );
  program.help();
  process.exit(1);
}

if (filePath) {
  done(
    keccak.mode(algo).init().update(
      fs.readFileSync(filePath)
    ).digest()
  );
} else if (message) {
  done(
    keccak.mode(algo).init().update(
      utf8.encode(message)
    ).digest()
  );
} else {
  console.log(
    colors.white.bold('ERROR: Must use with either -m [text] or -f [path]')
  );
  program.help();
  process.exit(1);
}
