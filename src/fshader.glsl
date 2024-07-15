#version 300 es

precision highp float;
precision highp int;

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define __INJECTS__
#ifdef __INJECTS__
#define LENGTH (0)
#define FILTER(h) (false)
#endif

uniform uint thread;
uniform uint iteration;
uniform uint hashData[LENGTH];
out vec4 outColor;

void main() {
    uint data[LENGTH];
    for (int i = 0; i < LENGTH; i++) data[i] = hashData[i];

    uint timestamp = data[1];
    for (uint iter = 0u; iter < iteration; iter++) {
        data[1] = timestamp - iter * thread - uint(gl_FragCoord.x);
        // 避免出现溢出的情况
        if (data[1] > timestamp) break;

        uint h[] = uint[](
            0x67452301u,
            0xEFCDAB89u,
            0x98BADCFEu,
            0x10325476u,
            0xC3D2E1F0u
        );

        for (int chunk = 0; chunk < LENGTH / 16; chunk++) {
            uint w[80];
            for (int i = 0; i < 16; i++) w[i] = data[chunk * 16 + i];
            for (int i = 16; i < 80; i++) w[i] = ROTL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

            uint a = h[0];
            uint b = h[1];
            uint c = h[2];
            uint d = h[3];
            uint e = h[4];
            uint f;
            uint k;
            uint t;

            for (int i = 0; i < 80; i++) {
                if (i < 20) {
                    f = d ^ (b & (c ^ d));
                    k = 0x5A827999u;
                } else if (i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1u;
                } else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDCu;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6u;
                }
                t = ROTL(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = ROTL(b, 30);
                b = a;
                a = t;
            }

            h[0] += a;
            h[1] += b;
            h[2] += c;
            h[3] += d;
            h[4] += e;
        }

        if (FILTER(h)) {
            outColor = vec4(
                float((data[1] >>  0) & 0xFFu) / 255.,
                float((data[1] >>  8) & 0xFFu) / 255.,
                float((data[1] >> 16) & 0xFFu) / 255.,
                float((data[1] >> 24) & 0xFFu) / 255.
            );
            return;
        }
    }

    outColor = vec4(0., 0., 0., 0.);
}