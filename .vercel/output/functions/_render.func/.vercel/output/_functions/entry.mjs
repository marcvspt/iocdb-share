import { renderers } from './renderers.mjs';
import { c as createExports } from './chunks/entrypoint_Cfy46gRK.mjs';
import { manifest } from './manifest_CMqNMmDA.mjs';

const _page0 = () => import('./pages/_image.astro.mjs');
const _page1 = () => import('./pages/api/analyze/_analyze_.astro.mjs');
const _page2 = () => import('./pages/api/type.astro.mjs');
const _page3 = () => import('./pages/index.astro.mjs');

const pageMap = new Map([
    ["node_modules/astro/dist/assets/endpoint/generic.js", _page0],
    ["src/pages/api/analyze/[analyze].astro", _page1],
    ["src/pages/api/type.ts", _page2],
    ["src/pages/index.astro", _page3]
]);
const serverIslandMap = new Map();
const _manifest = Object.assign(manifest, {
    pageMap,
    serverIslandMap,
    renderers,
    middleware: () => import('./_noop-middleware.mjs')
});
const _args = {
    "middlewareSecret": "e3342dbd-ddb1-4e31-a9de-a43bf9ce5f7a",
    "skewProtection": false
};
const _exports = createExports(_manifest, _args);
const __astrojsSsrVirtualEntry = _exports.default;

export { __astrojsSsrVirtualEntry as default, pageMap };
