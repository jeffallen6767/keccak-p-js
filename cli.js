#!/usr/bin/env node
var keccak = require("./index"),
  colors = require("colors"),
	fs = require('fs'),
  program = require('commander'),
  pkg = require('./package.json'),
  version = pkg.version,
  KECCAK_MODES = {
    "sha": [
      "224", "256", "384", "512"
    ],
    "shake": [
      "128", "256"
    ]
  },
  make_red = function make_red(txt) {
    return colors.red(txt);
  };
  
program
  .version(version)
  .option('-f, --file', 'file to apply keccak');

program
  .command('sha <mode> [text]')
  .description('run keccak sha-3-<mode> where mode is one of 224, 256, 384 or 512')
  .action(function(m, t, c) {
    var mode = KECCAK_MODES.sha.indexOf(m) !== -1 && "SHA-3-" + m,
      file = c.parent.file ? t : false,
      text = file ? false : t,
      k,
      result;
    if (mode && (file || text)) {
      try {
        k = keccak.mode(mode).init();
        if (text) {
          result = k.update(text).digest();
        } else {
          result = k.update(fs.readFileSync(file)).digest();
        }
        console.log(result);
      } catch (e) {
        console.error(make_red(e.message));
      }
    } else {
      program.outputHelp(make_red);
    }
  });

// TODO: shake

program
  .parse(process.argv);
