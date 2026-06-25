import * as m from "/home/rizk/agis/.tmp/package-smoke/package/dist/index.js";
const keys = Object.keys(m);
if (keys.length === 0) { console.error('SDK_IMPORT_EMPTY'); process.exit(1); }
console.log('SDK_IMPORT_OK (' + keys.length + ' exports)');
console.log('Sample exports: ' + keys.slice(0, 5).join(', '));