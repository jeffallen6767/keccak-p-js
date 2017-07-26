/*
keccak-p adapted from:

Pseudo-code description @ http://keccak.noekeon.org/specs_summary.html

NOTE: JavaScript has no 64-bit unsigned integer datatype, 
so we represent them as [uInt32low, uInt32high]

*/

/*
b = [25, 50, 100, 200, 400, 800, 1600],
  w = [1, 2, 4, 8, 16, 32, 64],
*/
var 
  KECCAK_ROUNDS = 24,
  
  ROWS_X = 5,
  COLS_Y = 5,
  BITS_Z = 64,
  
  BITS_IN_BYTE = 8,
  
  UINT64_BYTES = BITS_Z / BITS_IN_BYTE,
  UINT32_BYTES = UINT64_BYTES / 2,
  
  BYTES_PER_ROW = COLS_Y * UINT64_BYTES,
  NUM_STATE_BYTES = ROWS_X * BYTES_PER_ROW,
  
  NUM_STATE_32_INTS = NUM_STATE_BYTES / UINT32_BYTES,
  
  Y_OFFSET = NUM_STATE_32_INTS / ROWS_X,
  
  BIT_32_DIGITS = "00000000000000000000000000000000",
  getBit32digits = function(val) {
    var len = val.toString().length;
    return BIT_32_DIGITS.substr(len) + val;
  },
  HEX_32_DIGITS = "00000000",
  getHex32digits = function(val) {
    var len = val.toString().length;
    return HEX_32_DIGITS.substr(len) + val;
  },
  INT_32_DIGITS = "0000000000",
  getInt32digits = function(val) {
    var len = val.toString().length;
    return INT_32_DIGITS.substr(len) + val;
  },
  
  BYTE_MULT_32_1 = 16777216,
  BYTE_MULT_32_2 = 65536,
  BYTE_MULT_32_3 = 256,
  
  CRLF = "\n",
  
  KECCAK_MODES = {
    "SHA-3-224":{}, 
    "SHA-3-256":{}, 
    "SHA-3-384":{}, 
    "SHA-3-512":{},
    "SHAKE-128":{},
    "SHAKE-256":{}
  },
  KECCAK_MODE_KEYS = Object.keys(KECCAK_MODES);
/*
console.log("KECCAK_ROUNDS", KECCAK_ROUNDS);
console.log("ROWS_X", ROWS_X);
console.log("COLS_Y", COLS_Y);
console.log("BITS_Z", BITS_Z);
console.log("BITS_IN_BYTE", BITS_IN_BYTE);
console.log("UINT64_BYTES", UINT64_BYTES);
console.log("UINT32_BYTES", UINT32_BYTES);
console.log("BYTES_PER_ROW", BYTES_PER_ROW);
console.log("NUM_STATE_BYTES", NUM_STATE_BYTES);
console.log("NUM_STATE_32_INTS", NUM_STATE_32_INTS);
console.log("Y_OFFSET", Y_OFFSET);
*/
/*
+++ The round constants +++

RC[00][0][0] = 0000000000000001
RC[01][0][0] = 0000000000008082
RC[02][0][0] = 800000000000808A
RC[03][0][0] = 8000000080008000
RC[04][0][0] = 000000000000808B
RC[05][0][0] = 0000000080000001
RC[06][0][0] = 8000000080008081
RC[07][0][0] = 8000000000008009
RC[08][0][0] = 000000000000008A
RC[09][0][0] = 0000000000000088
RC[10][0][0] = 0000000080008009
RC[11][0][0] = 000000008000000A
RC[12][0][0] = 000000008000808B
RC[13][0][0] = 800000000000008B
RC[14][0][0] = 8000000000008089
RC[15][0][0] = 8000000000008003
RC[16][0][0] = 8000000000008002
RC[17][0][0] = 8000000000000080
RC[18][0][0] = 000000000000800A
RC[19][0][0] = 800000008000000A
RC[20][0][0] = 8000000080008081
RC[21][0][0] = 8000000000008080
RC[22][0][0] = 0000000080000001
RC[23][0][0] = 8000000080008008

*/
// uInt64 represented as x[uInt32lo, uInt32hi]
var iota_const = [
  [0x00000001,0x00000000], 
  [0x00008082,0x00000000], 
  [0x0000808a,0x80000000],
  [0x80008000,0x80000000], 
  [0x0000808b,0x00000000], 
  [0x80000001,0x00000000],
  [0x80008081,0x80000000], 
  [0x00008009,0x80000000], 
  [0x0000008a,0x00000000],
  [0x00000088,0x00000000], 
  [0x80008009,0x00000000], 
  [0x8000000a,0x00000000],
  [0x8000808b,0x00000000], 
  [0x0000008b,0x80000000], 
  [0x00008089,0x80000000],
  [0x00008003,0x80000000], 
  [0x00008002,0x80000000], 
  [0x00000080,0x80000000],
  [0x0000800a,0x00000000], 
  [0x8000000a,0x80000000], 
  [0x80008081,0x80000000],
  [0x00008080,0x80000000], 
  [0x80000001,0x00000000], 
  [0x80008008,0x80000000]
];

//console.log("rndc", rndc);
/*
var rotc = [
  1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
  27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
];

var piln = [
  10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
  15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
];
*/

/*
+++ The rho offsets +++

RhoOffset[0][0] =  0
RhoOffset[1][0] =  1
RhoOffset[2][0] = 62
RhoOffset[3][0] = 28
RhoOffset[4][0] = 27
RhoOffset[0][1] = 36
RhoOffset[1][1] = 44
RhoOffset[2][1] =  6
RhoOffset[3][1] = 55
RhoOffset[4][1] = 20
RhoOffset[0][2] =  3
RhoOffset[1][2] = 10
RhoOffset[2][2] = 43
RhoOffset[3][2] = 25
RhoOffset[4][2] = 39
RhoOffset[0][3] = 41
RhoOffset[1][3] = 45
RhoOffset[2][3] = 15
RhoOffset[3][3] = 21
RhoOffset[4][3] =  8
RhoOffset[0][4] = 18
RhoOffset[1][4] =  2
RhoOffset[2][4] = 61
RhoOffset[3][4] = 56
RhoOffset[4][4] = 14
*/

var rhoOffset = [
  0, 1, 62, 28, 27, 
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14
];

var pi_step = [
  0,1, 20,21, 40,41, 10,11, 30,31,
  32,33, 2,3, 22,23, 42,43, 12,13,
  14,15, 34,35, 4,5, 24,25, 44,45,
  46,47, 16,17, 36,37, 6,7, 26,27,
  28,29, 48,49, 18,19, 38,39, 8,9
];
    
function bits(val) {
  return getBit32digits(val.toString(2));
}

function bit64(lo, hi) {
  return [bits(hi),bits(lo)].join("");
}

// x is uInt64 represented as x[uInt32lo, uInt32hi]
function ROTL64(x, y) {
  
  if (y) {
    var which = y < 32 ? 1 : 0,
      one = which ? y : y - 32, 
      two = 32 - one,
      hi, low, 
      result = [];
    
    if (which) {
      low = x[0];
      hi = x[1];
    } else {
      low = x[1];
      hi = x[0];
    }
    
    result[1] = (hi << one) | (low >>> two) & 0xFFFFFFFF;
    result[0] = (low << one) | (hi >>> two) & 0xFFFFFFFF;
    
    return result;
  } else {
    return x;
  }
}

function test_ROTL64(lo, hi, num) {
  console.log(" ");
  console.log("test_ROTL64["+num+"]");
  var result = ROTL64([lo,hi],num);
  console.log("     before", bit64(lo, hi));
  console.log("     after ", bit64(result[0], result[1]));
  console.log(" ");
}
//test_ROTL64(0x80008008,0x80000000,0);
//test_ROTL64(0x80008008,0x80000000,1);

function showState(state) {
  var result = [CRLF],
    len = state.length,
    i,
    hi,lo,
    y = 0;
  //console.log("showState state.len = ", len);
  for (i=0; i<len; i+=2) {
    lo = getHex32digits(state[i].toString(16));
    hi = getHex32digits(state[i+1].toString(16));
    result.push([hi,lo].join("").toUpperCase());
    if (++y > 4) {
      y = 0;
      result.push(CRLF);
    }
  }
  
  return result.join(" ");
}

function show_array(vals, width) {
  var len = vals.length,
    idx = -1,
    tmp = [],
    more,
    what;
  console.log("show_array", len, "@", width);
  while (++idx < len) {
    if (tmp.length === width) {
      more = idx < len ? "," : "";
      console.log(tmp.join(", ") + more);
      tmp = [];
    }
    tmp.push(
      vals[idx]
    );
  }
  if (tmp.length > 0) {
    console.log(tmp.join(", "));
  }
}

function sha3_keccakf(A) {
  
  //console.log("sha3_keccakf");
  //console.log("state["+A.length+"]", showState(A));
  
  var 
    B = [],
    C = [[0,0],[0,0],[0,0],[0,0],[0,0]],
    D = [[0,0],[0,0],[0,0],[0,0],[0,0]],
    E = [],
    
    lo = 0,
    hi = 1,
    
    i,
    
    p,q,r,s,t,u,v,w,x,y,z;
  
  for (i=0; i<KECCAK_ROUNDS; i++) {
    
    
    /* x,y maps to A[0..49], A[0] = int32high, A[1] = int32low of [x0,y0]
      0  1    2  3    4  5    6  7    8  9
    [x0,y0],[x1,y0],[x2,y0],[x3,y0],[x4,y0]
     10 11   12 13   14 15   16 17   18 19
    [x0,y1],[x1,y1],[x2,y1],[x3,y1],[x4,y1]
     20 21   22 23   24 25   26 27   28 29
    [x0,y2],[x1,y2],[x2,y2],[x3,y2],[x4,y2]
     30 31   32 33   34 35   36 37   38 39
    [x0,y3],[x1,y3],[x2,y3],[x3,y3],[x4,y3]
     40 41   42 43   44 45   46 47   48 49
    [x0,y4],[x1,y4],[x2,y4],[x3,y4],[x4,y4]
    */
    // θ (theta) step
    for (x=0; x<ROWS_X; x++) {
      // C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4]
      z = x * 2;
      C[x][lo] = A[z] ^ A[z+10] ^ A[z+20] ^ A[z+30] ^ A[z+40];
      C[x][hi] = A[z+1] ^ A[z+11] ^ A[z+21] ^ A[z+31] ^ A[z+41];
    }
    for (x=0; x<ROWS_X; x++) {
      // D[x] = C[x-1] xor rot(C[x+1],1)
      /*
      x=0,w=4,z=1
      x=1,w=0,z=2
      x=2,w=1,z=3
      x=3,w=2,z=4
      x=4,w=3,z=0
      */
      w = (x + 4) % ROWS_X;
      z = (x + 1) % ROWS_X;
      t = D[x];
      u = C[w];
      v = ROTL64(C[z],1);
      r = t[lo] = u[lo] ^ v[lo];
      p = t[hi] = u[hi] ^ v[hi];
      s = x * 2;
      for (y=0; y<COLS_Y; y++) {
        // A[x,y] = A[x,y] xor D[x]
        q = s + y * Y_OFFSET;
        A[q] ^= r;
        A[q+1] ^= p;
      }
    }
    //console.log(i + " After theta:", showState(A));
    
    // ρ (rho) step:
    for (y=0; y<COLS_Y; y++) {
      p = y * Y_OFFSET; // column
      for (x=0; x<ROWS_X; x++) {
        q = p + (x * 2); // low
        r = q + 1; // high
        s = A[q];
        t = A[r];
        u = y * ROWS_X;
        v = u + x;
        w = rhoOffset[v];
        z = ROTL64([s,t],w);
        B[q] = z[lo] >>> 0;
        B[r] = z[hi] >>> 0;
      }
    }
    //console.log(i + " After rho:", showState(B));
    
    // π (pi) step:
    /*
    26 27 28 29 20 21 22 23 24 25
    [3,2] [4,2] [0,2] [1,2] [2,2]
    
    16 17 18 19 10 11 12 13 14 15
    [3,1] [4,1] [0,1] [1,1] [2,1]
    
     6 7   8 9   0 1   2 3   4 5
    [3,0] [4,0] [0,0] [1,0] [2,0]
    
    46 47 48 49 40 41 42 43 44 45
    [3,4] [4,4] [0,4] [1,4] [2,4]
    
    36 37 38 39 30 31 32 33 34 35
    [3,3] [4,3] [0,3] [1,3] [2,3]
    */
    for (y=0; y<COLS_Y; y++) {
      p = y * Y_OFFSET; // column
      for (x=0; x<ROWS_X; x++) {
        q = p + (x * 2); // low
        r = q + 1; // high
        s = pi_step[q];
        t = s + 1;
        //console.log("pi ["+x+","+y+"] from:", q, r, " to:", s, t);
        E[s] = B[q];
        E[t] = B[r];
      }
    }
    //console.log(i + " After pi:", showState(E));
    
    // χ (chi) step
    for (y=0; y<COLS_Y; y++) {
      p = y * Y_OFFSET; // column
      for (x=0; x<ROWS_X; x++) {
        
        //y=1,p=10,x=0,q=0,r=10,s=12,t=14
        //y=1,p=10,x=1,q=2,r=12,s=14,t=16
        //y=1,p=10,x=2,q=4,r=14,s=16,t=18
        //y=1,p=10,x=3,q=6,r=16,s=18,t=10
        //y=1,p=10,x=4,q=8,r=18,s=10,t=12
        
        // calc the indexes
        r = p + (x * 2);
        s = p + (((x + 1) % ROWS_X) * 2);
        t = p + (((x + 2) % ROWS_X) * 2);
        
        u = r + 1;
        v = s + 1;
        w = t + 1;
        // lows
        A[r] = E[r] ^ ((~E[s]) & E[t]);
        // highs
        A[u] = E[u] ^ ((~E[v]) & E[w]);
      }
    }
    //console.log(i + " After chi:", showState(A));
    
    // ι (iota) step
    p = iota_const[i];
    A[0] ^= p[lo];
    A[1] ^= p[hi];
    //console.log(i + " After iota:", showState(A));
  }
  
}

var keccak = {
  "mode": function(mode) {
    
    if (KECCAK_MODE_KEYS.indexOf(mode) === -1) {
      throw new Error("Keccak.mode requires one of: " + KECCAK_MODE_KEYS.join());
    }
    
    var 
      parts = mode.split("-"),
      
      modeBits = parts[parts.length-1] - 0,
      modeBytes = modeBits / BITS_IN_BYTE,
      
      state, 
      uInt8state, 
      uInt32state,
      rsiz, 
      pt,
      len,
      inputType,
      i;
    
    //console.log("mode", mode, "modeBits", modeBits, "modeBytes", modeBytes);
    
    var instance = {
      "init": function() {
        // A new ArrayBuffer object of size, in bytes, of the array buffer to create.. Its contents are initialized to 0.
        // see: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer
        // 64 bits * 25 = 1600 bits
        state = new ArrayBuffer(NUM_STATE_BYTES);
        // create 2 views of the bits, see: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray
        // 1st, a 8 bit unsigned integer view, see: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array
        uInt8state = new Uint8Array(state);
        // 2nd, a 32 bit unsigned integer view, see: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint32Array
        uInt32state = new Uint32Array(state);
        // length of digest requested
        //mdlen = modeBits / 4;
        // bytes of size for sponge function?
        rsiz = NUM_STATE_BYTES - 2 * modeBytes;
        //rsiz = NUM_STATE_BYTES;
        // byte pointer
        pt = 0;
        
        //console.log("init mode", mode, "modeBytes", modeBytes, "rsiz", rsiz);
        
        return instance;
      },
      "update": function(input) {
        // accept string or array of bytes
        //console.log(typeof input);
        switch (typeof input) {
          case "string":
            inputType = 0;
            break;
          default:
            switch (typeof input[0]) {
              case "number":
                inputType = 1;
                break;
              case "string":
                inputType = 2;
                break;
              default:
                throw new Error("update accepts string 'abc', array decimal [97,98,99], array hex [0x61,0x62,0x63] or ['61','62','63'] only!");
                break;
            }
            break;
        }
        //inputType = Array.isArray(input);
        len = input.length;
        //console.log("update", inputType ? "array" : "string", len);
        
        //if (inputType) {
        //  show_array(input, 16);
        //}
        
        var
          j,
          
          a,b,c,d,e,f,g,
          
          hi, lo,
          
          hex;
        
        j = pt;
        for (i = 0; i < len; i++) {
          a = input[i];
          switch (inputType) {
            case 0:
              b = a.charCodeAt();
              break;
            case 1:
              b = a;
              break;
            case 2:
              b = parseInt(a, 16);
              break;
            default:
              throw new Error("update unknown inputType: " + inputType);
              break;
          } 
          /*
          c = b.toString(2);
          d = c.length;
          e = "00000000".substr(d) + c;
          hi = e.slice(0,4);
          lo = e.slice(4);
          hex = b.toString(16);
          console.log(i,a,b,c,d,e, "hi", hi, "lo", lo, "hex", hex);
          */
          uInt8state[j++] ^= b;
          if (j >= rsiz) {
            sha3_keccakf(uInt32state);
            j = 0;
          }
        }
        pt = j;

        return instance;
      },
      "digest": function() {
        //console.log("digest", pt, rsiz);
        
        var hash = [],
          tmp;
        
        uInt8state[pt] ^= 0x06;
        uInt8state[rsiz - 1] ^= 0x80;
        
        sha3_keccakf(uInt32state);

        for (i = 0; i < modeBytes; i++) {
          tmp = uInt8state[i].toString(16);
          len = tmp.length;
          hash[i] = "00".substr(len) + tmp;
        }

        return hash.join("");
      }
    };
    return instance;
  }
};

module.exports = keccak;
