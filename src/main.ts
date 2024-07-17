import { createApp } from 'petite-vue';
import {
    readPrivateKey,
    reformatKey,
    SecretSubkeyPacket,
} from 'openpgp/lightweight';
import { createVanityKey } from './vanity-key.ts';
import tadaData from './tada.ogg?inline';
import {
    EllipticCurveName,
    GenerateKeyOptions,
    KeyPair,
    Subkey,
    UserID,
} from 'openpgp/lightweight';
import 'terminal.css';

const tada = new Audio(tadaData);

const app: {
    keyType: EllipticCurveName | '2048' | '3072' | '4096',
    userIDInput: UserID,
    userID: UserID[],
    thread: number,
    iteration: number,
    pattern: string,
    patternNumber: string,
    patternLength: number,
    vanitySubkey: boolean,
    notification: {
        sfx: boolean,
        ntfy: boolean,
        ntfyTopic: string,
    },
    nonstopMode: boolean,
    backTime: number,
    estimatedHashCount: bigint,
    subkeyCombinerArmoredA: string,
    subkeyCombinerArmoredB: string,

    running: boolean,
    generatedKey?: KeyPair,

    hashCount: number,
    runningTime: number,

    formatFingerprint: (x: string) => string,

    mounted: () => void,
    addUserID: () => void,
    patternHelper: () => void,
    toggleKeygen: () => Promise<void>,
    subkeyCombine: () => Promise<void>,
} = {
    keyType: 'curve25519',
    userIDInput: {
        name: '',
        email: '',
    },
    userID: [],
    thread: 1048576,
    iteration: 512,
    pattern: '',
    patternNumber: '0123456789ABCDEFXXXX'[Math.floor(Math.random() * 20)],
    patternLength: 6 + Math.floor(Math.random() * 3),
    vanitySubkey: false,
    notification: {
        sfx: false,
        ntfy: false,
        ntfyTopic: '',
    },
    nonstopMode: false,
    get backTime() {
        return this.thread * this.iteration;
    },
    get estimatedHashCount() {
        let count = 0;
        let countX = 0;
        for (const c of this.pattern.toUpperCase()) {
            if ('0123456789ABCDEF'.includes(c)) {
                count++;
            } else if (c === 'X') {
                countX++;
            }
        }
        return 16n ** BigInt(count + (countX ? countX - 1 : 0));
    },
    subkeyCombinerArmoredA: '',
    subkeyCombinerArmoredB: '',
    running: false,
    generatedKey: undefined,
    hashCount: 0,
    runningTime: 0,

    formatFingerprint(x) {
        return x.toUpperCase().match(/[^]{1,4}/g)!.join(' ');
    },

    mounted() {
        this.patternHelper();
        if (/iPhone|iPad|iPod|Android/i.test(navigator.userAgent)) {
            this.thread = 1024;
            this.iteration = 256;
        }
    },

    addUserID() {
        if (!this.userIDInput.name || !this.userIDInput.email) return;
        this.userID.push({...this.userIDInput});
        this.userIDInput.name = this.userIDInput.email = '';
    },

    patternHelper() {
        this.pattern = this.formatFingerprint(('*'.repeat(40 - this.patternLength) + this.patternNumber.repeat(this.patternLength)));
    },

    async toggleKeygen() {
        if (this.running) {
            this.running = false;
            return;
        }
        if (!this.userID.length) {
            if (!this.userIDInput.name && !this.userIDInput.email) {
                this.userIDInput.name = 'Dummy';
                this.userIDInput.email = 'dummy@example.com';
            }
            this.addUserID();
        }
        this.hashCount = 0;
        this.runningTime = 0;
        this.running = true;
        try {
            const options: GenerateKeyOptions = {
                userIDs: this.userID,
            };
            switch (this.keyType) {
                case 'curve25519':
                case 'p256':
                case 'p384':
                case 'p521':
                case 'brainpoolP256r1':
                case 'brainpoolP384r1':
                case 'brainpoolP512r1':
                    options.type = 'ecc';
                    options.curve = this.keyType;
                    break;
                case '2048':
                case '3072':
                case '4096':
                    options.type = 'rsa';
                    options.rsaBits = parseInt(this.keyType);
                    break;
            }
            do {
                const generatedKey = await createVanityKey(
                    options,
                    this.pattern,
                    this.thread,
                    this.iteration,
                    (h, t) => {
                        this.hashCount = h;
                        this.runningTime = t;
                    },
                    () => !this.running,
                    this.vanitySubkey,
                );
                if (generatedKey) {
                    this.generatedKey = generatedKey;
                    const armor = generatedKey.privateKey.armor();
                    const created = generatedKey.publicKey.getCreationTime().toISOString();
                    const fingerprint = this.formatFingerprint(generatedKey.publicKey.getFingerprint());
                    console.log(armor);
                    console.log('Created:', created);
                    console.log('Fingerprint:', fingerprint);
                    if (this.notification.sfx) {
                        tada.play();
                    }
                    if (this.notification.ntfy && this.notification.ntfyTopic) {
                        fetch(`https://ntfy.sh/`, {
                            method: 'POST',
                            body: JSON.stringify({
                                topic: this.notification.ntfyTopic,
                                markdown: true,
                                title: 'webgl-vanity-gpg 计算出了新的密钥！',
                                message: 'Fingerprint: `' + fingerprint + '`\n\nCreated: ' + created + '\n\n请回到打开的 webgl-vanity-gpg 页面，在页面上/控制台中查看生成的密钥。',
                            }),
                        });
                    }
                }
            } while (this.running && this.nonstopMode);
        } catch (err) {
            alert(err);
        } finally {
            this.running = false;
        }
    },

    async subkeyCombine() {
        try {
            const [privateKeyA, privateKeyB] = await Promise.all(
                [this.subkeyCombinerArmoredA, this.subkeyCombinerArmoredB]
                    .map(e => readPrivateKey({ armoredKey: e }))
            );
            privateKeyA.subkeys.push(
                new Subkey(
                    Object.assign(new SecretSubkeyPacket, privateKeyB.keyPacket),
                    privateKeyA.toPublic(),
                ),
                ...privateKeyB.subkeys,
            );
            const combinedKey = await reformatKey({
                privateKey: privateKeyA,
                userIDs: privateKeyA.users.map(e => e.userID!),
                date: privateKeyA.keyPacket.created,
                format: 'object',
            });
            const el = document.createElement('a');
            el.href = `data:text/plain;charset=utf-8,${encodeURIComponent(combinedKey.privateKey.armor())}`;
            el.download = `${combinedKey.privateKey.getFingerprint().toUpperCase()}-sec.asc`;
            el.click();
        } catch (err) {
            alert(err);
        }
    },
}

createApp(app).mount();
