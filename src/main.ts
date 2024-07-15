import { createApp } from 'petite-vue';
import { createVanityKey } from './vanity-key.ts';
import type {
    EllipticCurveName,
    GenerateKeyOptions,
    KeyPair,
    UserID,
} from 'openpgp/lightweight';
import 'terminal.css';

const app: {
    keyType: EllipticCurveName | '2048' | '3072' | '4096',
    userIDInput: UserID,
    userID: UserID[],
    thread: number,
    iteration: number,
    pattern: string,
    patternNumber: string,
    patternLength: number,
    backTime: number,
    estimatedHashCount: bigint,

    running: boolean,
    generatedKey?: KeyPair,

    hashCount: number,
    runningTime: number,

    mounted: () => void,
    addUserID: () => void,
    patternHelper: () => void,
    toggleKeygen: () => Promise<void>,
} = {
    keyType: 'curve25519',
    userIDInput: {
        name: '',
        email: '',
    },
    userID: [],
    thread: 16384,
    iteration: 4096,
    pattern: '',
    patternNumber: '0123456789ABCDEF'[Math.floor(Math.random() * 16)],
    patternLength: 6 + Math.floor(Math.random() * 3),
    get backTime() {
        return this.thread * this.iteration;
    },
    get estimatedHashCount() {
        return 16n ** BigInt(this.pattern.split('').filter(e => '0123456789ABCDEFabcdef'.includes(e)).length);
    },
    running: false,
    generatedKey: undefined,
    hashCount: 0,
    runningTime: 0,

    mounted() {
        this.patternHelper();
    },

    addUserID() {
        if (!this.userIDInput.name || !this.userIDInput.email) return;
        this.userID.push({...this.userIDInput});
        this.userIDInput.name = this.userIDInput.email = '';
    },

    patternHelper() {
        this.pattern = ('*'.repeat(40 - this.patternLength) + this.patternNumber.repeat(this.patternLength))
            .match(/[^]{1,4}/g)!
            .join(' ');
    },

    async toggleKeygen() {
        if (this.running) {
            this.running = false;
            return;
        }
        if (!this.userID.length || (this.userIDInput.name && this.userIDInput.email)) {
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
            this.generatedKey = await createVanityKey(
                options,
                this.pattern,
                this.thread,
                this.iteration,
                (h, t) => {
                    this.hashCount = h;
                    this.runningTime = t;
                },
                () => !this.running,
            );
        } catch (err) {
            alert(err);
        } finally {
            this.running = false;
        }
    },
}

createApp(app).mount();
