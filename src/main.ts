import { createApp } from 'petite-vue';
import {
    readPrivateKey,
    reformatKey,
    SecretSubkeyPacket,
} from 'openpgp/lightweight';
import { TarWriter } from '@gera2ld/tarjs';
import { patternToFilter, createVanityKey } from './vanity-key.ts';
import tadaData from './tada.ogg?inline';
import silenceData from './near-silence.ogg?inline';
import {
    EllipticCurveName,
    KeyOptions,
    KeyPair,
    Subkey,
    UserID,
} from 'openpgp/lightweight';
import 'terminal.css';

const tada = new Audio(tadaData);

// 通过播放音频阻止浏览器降低setTimeout的频率
// 完全静音的音频是没有效果的……
// ffmpeg -f lavfi -i "sine=frequency=1:duration=1" -c:a libopus -ar 8k -b:a 1k -movflags +faststart -fflags +bitexact -map_metadata -1 -dn near-silence.ogg
const silence = new Audio(silenceData);
silence.volume = .01;
silence.loop = true;

const app: {
    keyType: EllipticCurveName | '2048' | '3072' | '4096',
    userIDInput: UserID,
    userID: UserID[],
    thread: number,
    iteration: number,
    pattern: string,
    patternNumber: string,
    patternLength: number,
    filter: string,
    vanitySubkey: boolean,
    notification: {
        sfx: boolean,
        ntfy: boolean,
        ntfyTopic: string,
    },
    nonstopMode: boolean,
    saveToDirectory: boolean,
    saveToDirectoryHandle?: FileSystemDirectoryHandle,
    backTime: number,
    estimatedHashCount: bigint,
    subkeyCombinerArmoredA: string,
    subkeyCombinerArmoredB: string,

    running: boolean,
    generatedKey?: KeyPair,
    generatedKeyHistory: KeyPair[],

    hashCount: number,
    runningTime: number,

    formatFingerprint: (x: string) => string,

    mounted: () => void,
    addUserID: () => void,
    patternHelper: () => void,
    setSaveDirectory: () => Promise<void>,
    showAutoFilter: () => void,
    toggleKeygen: () => Promise<void>,
    bulkDownload: () => Promise<void>,
    subkeyCombine: () => Promise<void>,
} = {
    keyType: 'curve25519Legacy',
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
    filter: '',
    vanitySubkey: false,
    notification: {
        sfx: false,
        ntfy: false,
        ntfyTopic: '',
    },
    nonstopMode: false,
    saveToDirectory: false,
    saveToDirectoryHandle: undefined,
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
    generatedKeyHistory: [],
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

    async setSaveDirectory() {
        if (!window.showDirectoryPicker) {
            return alert('你的浏览器不支持 File System Access API。\n参见：https://caniuse.com/native-filesystem-api');
        }
        this.saveToDirectoryHandle = await window.showDirectoryPicker({ mode: 'readwrite' }).catch(() => undefined);
    },

    showAutoFilter() {
        alert(patternToFilter(this.pattern));
    },

    async bulkDownload() {
        if (!this.generatedKeyHistory.length) return;
        const tar = new TarWriter;
        this.generatedKeyHistory.forEach(e => tar.addFile(`${e.privateKey.getFingerprint().toUpperCase()}-sec.asc`, e.privateKey.armor()));
        const el = document.createElement('a');
        el.href = URL.createObjectURL(await tar.write());
        el.download = 'vanity-keys.tar';
        el.click();
        URL.revokeObjectURL(el.href);
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
        silence.play();
        try {
            const options: KeyOptions = {
                userIDs: this.userID,
            };
            switch (this.keyType) {
                case 'curve25519Legacy':
                case 'nistP256':
                case 'nistP384':
                case 'nistP521':
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
                    this.filter.replaceAll('\n', ' ') || patternToFilter(this.pattern),
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
                    this.generatedKeyHistory.push(generatedKey);
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
                                message: 'Fingerprint: `' + this.formatFingerprint(generatedKey.publicKey.getFingerprint()) + '`\n\nCreated: ' + generatedKey.publicKey.getCreationTime().toISOString() + '\n\n请回到打开的 webgl-vanity-gpg 页面，在页面上/控制台中查看生成的密钥。',
                            }),
                        });
                    }
                    if (this.saveToDirectory && this.saveToDirectoryHandle) {
                        const fileHandle = await this.saveToDirectoryHandle.getFileHandle(`${generatedKey.privateKey.getFingerprint().toUpperCase()}-sec.asc`, { create: true });
                        const stream = await fileHandle.createWritable();
                        await stream.write(new Blob([generatedKey.privateKey.armor()]));
                        await stream.close();
                    }
                }
            } while (this.running && this.nonstopMode);
        } catch (err) {
            alert(err);
        } finally {
            this.running = false;
            silence.pause();
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
