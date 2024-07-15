import childProcess from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { defineConfig, Plugin, TransformResult } from 'vite';
import { createHtmlPlugin } from 'vite-plugin-html';
import { visualizer } from 'rollup-plugin-visualizer';

// https://vitejs.dev/config/
export default defineConfig({
    base: '',
    plugins: [
        (() => {
            // Download shader_minifier executable from:
            // https://github.com/laurentlb/shader-minifier

            if (process.env.NODE_ENV !== 'production') return;

            if (childProcess.spawnSync('shader_minifier', ['--help']).error) {
                console.warn('Shader minifier is not available.');
                return;
            }

            return ({
                name: 'minify-shader',
                async transform(code, id) {
                    if (id.endsWith('.glsl?raw')) {
                        const temp = path.join(os.tmpdir(), Math.random().toString(36).substring(2, 10));
                        const result: TransformResult = {
                            code: '',
                            map: null,
                        };
                        try {
                            await new Promise((resolve, reject) => {
                                const p = childProcess.spawn('shader_minifier', [
                                    '-o', temp,
                                    '--format', 'text',
                                    '--aggressive-inlining',
                                    '--preserve-externals',
                                    id.replace(/\?raw$/g, ''),
                                ]);
                                p.on('close', resolve);
                                p.on('error', reject);
                            });
                            result.code = `export default ${JSON.stringify(await fs.promises.readFile(temp, { encoding: 'utf-8' }))}`;
                        } finally {
                            await fs.promises.unlink(temp).catch(() => {});
                        }
                        return result;
                    }
                }
            } as Plugin);
        })(),
        createHtmlPlugin({
            minify: {
                collapseWhitespace: true,
                collapseBooleanAttributes: true,
                decodeEntities: true,
                removeComments: true,
                removeAttributeQuotes: false,
                removeRedundantAttributes: true,
                removeScriptTypeAttributes: true,
                removeStyleLinkTypeAttributes: true,
                removeEmptyAttributes: true,
                useShortDoctype: true,
                processConditionalComments: true,
                sortAttributes: true,
                sortClassName: true,
                minifyCSS: true,
                minifyJS: true,
                minifyURLs: false,
            },
        }),
    ],
    build: {
        chunkSizeWarningLimit: Infinity,
        target: 'esnext',
        rollupOptions: {
            plugins: [
                visualizer({
                    gzipSize: true,
                    brotliSize: true,
                }),
            ],
        },
    },
});
