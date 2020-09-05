//  ===============================================================
//  SHA1.ts
//  Module that replicates the SHA-1 Cryptographic Hash
//  function in Typescript.
//  ===============================================================

// Main variables
const CHAR_SIZE: number = 8;

/**
 *  Adds padding to binary/hex string represention
 *  @Example
 *  pad("10011", 8); // "00010011"
 */
function pad(str: string, bits: number): string {
    let res = str;
    while (res.length % bits !== 0) {
        res = '0' + res;
    }
    return res;
}

/**
 * Separates string into chunks of the same size
 * @example
 * chunkify("this is a test", 2); // ["th", "is", " i", "s ", "a ", "te", "st"]
 */
function chunkify(str: string, size: number): string[] {
    const chunks = [];
    for (let i = 0; i < str.length; i += size) {
        chunks.push(str.slice(i, i + size))   
    }
    return chunks;
}

/**
 * Rotates string representation of bits to the left
 *
 * Bits - string representation of bits
 * Turns - number of rotations to make
 * @example
 * rotateLeft("1011", 3); // "1101"
 */

function rotateLeft(bits: string, turns: number): string {
    return bits.substr(turns) + bits.substr(0, turns);
}

/**
 * Pre-Processes message to feed the algorith loop
 * Message- message to pre-process
 */

function preProcess (message: string): string {
    // Convert message to binary representation padded to
    // 8 bits, and add 1
    let m = message.split('')
        .map(e => e.charCodeAt(0))
        .map(e => e.toString(2))
        .map(e => pad(e, 8))
        .join('') + '1';

        // Length message by adding empty bits (0)
        while (m.length % 512 !== 488) {
            m += '0';
        }

        // length of message in binary, padded, and extended
        // to a 64 bits representation
        let ml = (message.length * CHAR_SIZE).toString(2);
        ml = pad(ml, 8);
        ml = '0'.repeat(64 - ml.length) + ml;
        
        return m + ml;
}

/**
 * Hashes message using SHA-1 Cryptographic Hash Function
 * 
 * message - message to hash
 * return the message digest  (hash value)
 */

export function SHA1 (message: string): string {
    // Main Variables
    let H0 = 0x67452301;
    let H1 = 0xEFCDAB89;
    let H2 = 0x98BADCFE;
    let H3 = 0x10325476;
    let H4 = 0xC3D1E1F0;

    // pre-process message and split into 512 bit chunks
    const bits = preProcess(message);
    const chunks = chunkify(bits, 512);

    chunks.forEach(function(chunk, i) {
        // Break each chunk into 16 32-bits words
        const words =  chunkify(chunk, 32);

        // Extend 16 32-bits words to 80 32-bits words
        for (let i = 16; i < 80; i++) {
            const val = [words[i - 3], words[i - 8], words[i - 14], words[i -16]]
                .map(e => parseInt(e, 2))
                .reduce((acc, curr) => curr ^ acc, 0);
            const bin = (val >>> 0).toString(2);
            const paddedBin = pad(bin, 32);
            const word = rotateLeft(paddedBin, 1);
            words.push(word);
        }

        // Initilize variables for this chunk
        let [a,b, c, d, e] = [H0, H1, H2, H3, H4];

        for (let i = 0; i < 80; i++) {
            let f, k;
            if (i < 20) {
                f = (b & c) | (~b & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            // make sure f is unsigned
            f >>>= 0;
            
            const aRot = rotateLeft(pad(a.toString(2), 32), 5);
            const aInt = parseInt(aRot, 2) >>> 0;
            const wordInt = parseInt(words[i], 2) >>> 0;
            const t = aInt + f + e + k + wordInt;
            e = d >>> 0;
            d = c >>> 0;
            const bRot = rotateLeft(pad(b.toString(2), 32), 30);
            c = parseInt(bRot, 2) >>> 0;
            b = a >>> 0;
            a = t >>> 0;
        }

        // Add values for this chunk to main hash variables (unsigned)
        H0 = (H0 + a) >>> 0;
        H1 = (H1 + b) >>> 0;
        H2 = (H2 + c) >>> 0;
        H3 = (H3 + d) >>> 0;
        H4 = (H4 + e) >>> 0;
    });

    // Combine hash values of main hash variables and return
    const HH = [H0, H1, H2, H3, H4]
        .map(e => e.toString(16))
        .map(e => pad(e, 8))
        .join('')
    return HH;
};

console.log(SHA1('Luis')); // 0c36b43f39159e97872bc39576cbf904fc88b34b
