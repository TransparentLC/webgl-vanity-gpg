import {
    generateKey,
    readPrivateKey,
    reformatKey,
} from 'openpgp/lightweight';
import type {
    GenerateKeyOptions,
    KeyPair,
    PrivateKey,
} from 'openpgp/lightweight';

import vshaderString from './vshader.glsl?raw';
import fshaderString from './fshader.glsl?raw';

// SHA-1测试向量及中间值：
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf

const editPrivateKeyCreationTime = async (privateKey: PrivateKey, created: Date): Promise<KeyPair> => {
    privateKey = await readPrivateKey({armoredKey: privateKey.armor()});
    await Promise.all(
        [privateKey.keyPacket, ...privateKey.subkeys.map(e => e.keyPacket)]
            .map(e => {
                e.created = created;
                // @ts-ignore
                // computeFingerprintAndKeyID not in d.ts
                // https://github.com/openpgpjs/openpgpjs/blob/a0337780b77093716ba92acb4a70b3bb5ceec87d/src/packet/public_key.js#L200
                return e.computeFingerprintAndKeyID();
            })
    );
    return await reformatKey({
        privateKey,
        userIDs: privateKey.users.map(e => e.userID!),
        date: created,
        format: 'object',
    });
};

const swap32 = (x: number) => (
    ((x &   0xFF) << 24) |
    ((x & 0xFF00) <<  8) |
    ((x >>  8) & 0xFF00) |
    ((x >> 24) &   0xFF)
) >>> 0;

export const patternToFilter = (pattern: string) => {
    pattern = pattern.replaceAll(' ', '');
    if (pattern.length != 40) throw new Error('Invalid pattern');
    return [
        ...[0, 8, 16, 24, 32].map((e, i) => {
            const s = pattern.substring(e, e + 8);
            let mask = '';
            let value = '';
            let activated = false;
            for (let i = 0; i < 8; i++) {
                if (s[i].match(/[\da-f]/gi)) {
                    mask += 'F';
                    value += s[i].toUpperCase();
                    activated = true;
                } else {
                    mask += '0';
                    value += '0';
                }
            }
            return activated ? `(h[${i}] & 0x${mask}u) == 0x${value}u` : '';
        }),
        ...pattern.split('')
            .map((e, i) => e.toUpperCase() === 'X' ? i : null)
            .filter(Boolean)
            .reduce((acc, cur, idx, arr) => {
                const leftIndex = Math.floor(arr[idx - 1]! / 8);
                const rightIndex = Math.floor(cur! / 8);
                const leftDigit = 7 - arr[idx - 1]! % 8;
                const rightDigit = 7 - cur! % 8;
                if (idx) {
                    acc.push(`((h[${leftIndex}] ${rightDigit > leftDigit ? '<<' : '>>'} ${Math.abs(rightDigit - leftDigit) * 4}) & 0xF${'0'.repeat(rightDigit)}u) == (h[${rightIndex}] & 0xF${'0'.repeat(rightDigit)}u)`);
                    // console.log(arr[idx - 1], cur, acc[acc.length - 1]);
                }
                return acc;
            }, [] as string[]),
    ].filter(Boolean).join(' && ') || 'true';
}

export const createVanityKey = async (
    config: GenerateKeyOptions,
    filter: string,
    thread: number,
    iteration: number,
    progressCallback: (hash: number, time: DOMHighResTimeStamp) => void = () => {},
    checkAbort: (hash: number, time: DOMHighResTimeStamp) => boolean = () => false,
    vanitySubkey: boolean = false,
): Promise<KeyPair | undefined> => {
    const size = Math.round(Math.sqrt(thread));
    const canvas = new OffscreenCanvas(size, size);
    const gl = canvas.getContext('webgl2')!;
    let initialized = false;
    let program: WebGLProgram | undefined;
    let hashDataLocation: WebGLUniformLocation | undefined;
    let fingerprintDataWithoutHeader = new Uint8Array;
    let fingerprintData = new Uint8Array;
    let hashData = new ArrayBuffer(0);
    let hashDataU8 = new Uint8Array;
    let hashDataU32 = new Uint32Array;
    const resultData = new ArrayBuffer(canvas.width * canvas.height * 4);
    const resultDataU8 = new Uint8Array(resultData);
    const resultDataU32 = new Uint32Array(resultData);
    let hashCount = 0;
    const startTime = performance.now();

    return await new Promise<KeyPair | undefined>((resolve, reject) => {
        const run = async () => {
            try {
                if (gl.isContextLost()) throw new Error('WebGL context lost');

                const keypair: KeyPair = await generateKey({
                    ...config,
                    format: 'object',
                });

                fingerprintDataWithoutHeader = (vanitySubkey ? keypair.publicKey.subkeys[0] : keypair.publicKey).keyPacket.write();
                // console.log('Initial key:');
                // console.log(keypair.privateKey.armor());
                // console.log(keypair.publicKey.armor());
                // console.log('Fingerprint:', keypair.publicKey.getFingerprint());
                // console.log(keypair.privateKey.keyPacket.created.getTime() / 1e3, (keypair.privateKey.keyPacket.created.getTime() / 1e3).toString(16));

                if (!initialized) {
                    fingerprintData = new Uint8Array(fingerprintDataWithoutHeader.length + 3);
                    fingerprintData[0] = 0x99;

                    hashData = new ArrayBuffer(Math.ceil((fingerprintData.length + 1 + 8) / 64) * 64);
                    hashDataU8 = new Uint8Array(hashData);
                    hashDataU32 = new Uint32Array(hashData);

                    const vs = gl.createShader(gl.VERTEX_SHADER)!;
                    const fs = gl.createShader(gl.FRAGMENT_SHADER)!;
                    gl.shaderSource(vs, vshaderString);
                    gl.shaderSource(fs, fshaderString.replaceAll('#define __INJECTS__', Object.entries({
                        'FILTER(h)': filter,
                        LENGTH: hashDataU32.length,
                    }).map(([k, v]) => `#define ${k} (${v})`).join('\n')));
                    gl.compileShader(vs);
                    gl.compileShader(fs);
                    program = gl.createProgram()!;
                    gl.attachShader(program, vs);
                    gl.attachShader(program, fs);
                    gl.linkProgram(program);
                    gl.useProgram(program);
                    gl.uniform1ui(gl.getUniformLocation(program!, 'width')!, canvas.width);
                    gl.uniform1ui(gl.getUniformLocation(program!, 'height')!, canvas.height);
                    gl.uniform1ui(gl.getUniformLocation(program!, 'iteration')!, iteration);
                    hashDataLocation = gl.getUniformLocation(program!, 'hashData')!;

                    const ppos = gl.getAttribLocation(program, 'pos');
                    gl.enableVertexAttribArray(ppos);
                    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
                    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([
                        -1, -1,
                         1, -1,
                        -1,  1,
                        -1,  1,
                         1, -1,
                         1,  1,
                    ]), gl.STATIC_DRAW);
                    gl.vertexAttribPointer(ppos, 2, gl.FLOAT, false, 0, 0);

                    gl.clearColor(0, 0, 0, 0);
                    gl.clear(gl.COLOR_BUFFER_BIT);

                    initialized = true;
                }

                // 准备计算密钥指纹的数据：
                // 09 + 大端序uint16 public-key packet长度 + public-key packet（从version开始的部分）
                // reference request - How to generate fingerprint for PGP public key - Cryptography Stack Exchange
                // https://crypto.stackexchange.com/questions/32087
                fingerprintData.set(
                    [
                        (fingerprintDataWithoutHeader.length >> 8) & 0xFF,
                        (fingerprintDataWithoutHeader.length     ) & 0xFF,
                    ],
                    1,
                );
                fingerprintData.set(fingerprintDataWithoutHeader, 3);
                // console.log(fingerprintData);
                // console.log(Array.from(fingerprintData).map(e => e.toString(16).padStart(2, '0')).join(''));

                // 手动进行SHA-1的填充
                // 1是数据开始填充的0x80，8是结束填充的数据长度（以bit而不是byte为单位）
                // 先清空0x80所在的uint32，其他部分长度不变，都会被覆盖的
                hashDataU32[fingerprintData.length >> 2] = 0;
                hashDataU8.set(fingerprintData);
                hashDataU8[fingerprintData.length] = 0x80;
                // 输入的数据是按大端序排列的01 02 03 04
                // 对应到SHA-1输入的word/uint32就是0x01020304
                // 但是这个uint32在小端序下应该是04 03 02 01
                // 所以需要转换字节序
                for (let i = 0; i < hashDataU32.length; i++) hashDataU32[i] = swap32(hashDataU32[i]);
                hashDataU32[hashDataU32.length - 1] = fingerprintData.length * 8;
                gl.uniform1uiv(hashDataLocation!, hashDataU32);
                // console.log(hashDataU8);
                // console.log(Array.from(hashDataU8).map(e => e.toString(16).padStart(2, '0')).join(''));
                // console.log(hashDataU32);
                // console.log(Array.from(hashDataU32).map(e => e.toString(16).padStart(8, '0')).join(' '));

                // 修改后密钥的UNIX时间戳
                let timestamp: number = 0;

                // 用两个三角形重绘整个画布就相当于触发使用GPU进行的计算了
                // 对于每个密钥来说
                // 一共有thread个像素，每个像素尝试计算iteration个时间戳
                // 第0轮期间，第0个像素计算t-0……第thread-1个像素计算t-(thread-1)
                // 第1轮期间，第0个像素计算t-thread-0……第thread-1个像素计算t-thread-(thread-1)
                // 第iteration-1轮期间，第0个像素计算t-thread*(iteration-1)-0……第thread-1个像素计算t-thread*(iteration-1)-(thread-1)
                // 一共会计算thread*iteration个时间戳

                gl.drawArrays(gl.TRIANGLES, 0, 6);
                gl.readPixels(0, 0, canvas.width, canvas.height, gl.RGBA, gl.UNSIGNED_BYTE, resultDataU8);
                for (let i = 0; i < resultDataU32.length; i++) {
                    if (resultDataU32[i]) {
                        // 目标时间戳是0x01020304
                        // 大端序下应该是04 03 02 01
                        // 写入顺序是RGBA
                        // 所以在shader那边输出的应该是R=0x04 G=0x03 B=0x02 A=0x01
                        timestamp = resultDataU32[i];
                        // console.log('Found:', i, timestamp, timestamp.toString(16));
                        // console.log(resultDataU32);
                        break;
                    }
                }

                hashCount += Math.min(Math.floor(Date.now() / 1000), size * size * iteration);
                progressCallback(hashCount, performance.now() - startTime);

                if (timestamp) {
                    resolve(await editPrivateKeyCreationTime(keypair.privateKey, new Date(timestamp * 1000)));
                    // console.log([0x99, 0x00, 0x33, ...vanityKeypair.publicKey.keyPacket.write()].map(e => e.toString(16).padStart(2, '0')).join(''));
                } else if (checkAbort(hashCount, performance.now() - startTime)) {
                    resolve(undefined);
                } else {
                    setTimeout(run, 0);
                }
            } catch (err) {
                reject(err);
            }
        };
        // 使用setTimeout防止死循环卡死主线程
        setTimeout(run, 0);
    });
};
