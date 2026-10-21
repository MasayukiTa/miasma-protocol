// Reads the interface of a WebAssembly module: types, imports, exports,
// function count, memories and tables. No dependencies.
//
// Used by scripts/check-wasm-pkg.mjs to compare a freshly built web/pkg with
// the committed one. The code bytes of a wasm-bindgen build embed absolute
// build paths, so they differ between machines; the interface does not.

const KIND = ['func', 'table', 'memory', 'global', 'tag'];
const VALTYPE = {
  0x7f: 'i32',
  0x7e: 'i64',
  0x7d: 'f32',
  0x7c: 'f64',
  0x7b: 'v128',
  0x70: 'funcref',
  0x6f: 'externref',
};

class Reader {
  constructor(bytes) {
    this.b = bytes;
    this.p = 0;
  }
  u8() {
    if (this.p >= this.b.length) throw new Error('unexpected end of module');
    return this.b[this.p++];
  }
  u32() {
    let result = 0;
    let shift = 0;
    for (;;) {
      const byte = this.u8();
      result += (byte & 0x7f) * 2 ** shift;
      if ((byte & 0x80) === 0) return result;
      shift += 7;
      if (shift > 35) throw new Error('bad LEB128');
    }
  }
  name() {
    const len = this.u32();
    const end = this.p + len;
    if (end > this.b.length) throw new Error('name past end of module');
    const s = Buffer.from(this.b.subarray(this.p, end)).toString('utf8');
    this.p = end;
    return s;
  }
  valtype() {
    const t = this.u8();
    if (!(t in VALTYPE)) throw new Error(`unknown value type 0x${t.toString(16)}`);
    return VALTYPE[t];
  }
  limits() {
    const flag = this.u8();
    const min = this.u32();
    const max = flag & 1 ? this.u32() : null;
    return `${min}..${max === null ? '' : max}${flag & 2 ? ' shared' : ''}`;
  }
}

/** Returns a plain object describing the module interface (stable key order). */
export function describeWasm(bytes) {
  if (bytes.length < 8 || bytes[0] !== 0 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) {
    throw new Error('not a wasm module');
  }
  const r = new Reader(bytes);
  r.p = 8;
  const types = [];
  const imports = [];
  const funcTypeIdx = []; // for defined functions
  const exportsRaw = [];
  const memories = [];
  const tables = [];
  let importedFuncs = 0;
  let globals = 0;
  let codeCount = 0;
  let dataCount = null;
  let hasStart = false;

  while (r.p < bytes.length) {
    const id = r.u8();
    const size = r.u32();
    const end = r.p + size;
    if (end > bytes.length) throw new Error('section past end of module');
    switch (id) {
      case 1: {
        const n = r.u32();
        for (let i = 0; i < n; i++) {
          if (r.u8() !== 0x60) throw new Error('unsupported type form');
          const params = [];
          const results = [];
          for (let j = r.u32(); j > 0; j--) params.push(r.valtype());
          for (let j = r.u32(); j > 0; j--) results.push(r.valtype());
          types.push(`(${params.join(',')})->(${results.join(',')})`);
        }
        break;
      }
      case 2: {
        const n = r.u32();
        for (let i = 0; i < n; i++) {
          const module = r.name();
          const name = r.name();
          const kind = r.u8();
          let desc = '';
          if (kind === 0) {
            desc = types[r.u32()];
            importedFuncs++;
          } else if (kind === 1) {
            r.valtype();
            desc = r.limits();
          } else if (kind === 2) {
            desc = r.limits();
          } else if (kind === 3) {
            desc = `${r.valtype()} ${r.u8() ? 'mut' : 'const'}`;
            globals++;
          } else {
            throw new Error(`unsupported import kind ${kind}`);
          }
          imports.push({ module, name, kind: KIND[kind], desc });
        }
        break;
      }
      case 3: {
        const n = r.u32();
        for (let i = 0; i < n; i++) funcTypeIdx.push(r.u32());
        break;
      }
      case 4: {
        const n = r.u32();
        for (let i = 0; i < n; i++) {
          const t = r.valtype();
          tables.push(`${t} ${r.limits()}`);
        }
        break;
      }
      case 5: {
        const n = r.u32();
        for (let i = 0; i < n; i++) memories.push(r.limits());
        break;
      }
      case 7: {
        const n = r.u32();
        for (let i = 0; i < n; i++) {
          const name = r.name();
          const kind = r.u8();
          const index = r.u32();
          exportsRaw.push({ name, kind, index });
        }
        break;
      }
      case 8:
        hasStart = true;
        break;
      case 10:
        codeCount = r.u32();
        break;
      case 12:
        dataCount = r.u32();
        break;
      default:
        break;
    }
    r.p = end;
  }

  const exports = exportsRaw.map(({ name, kind, index }) => {
    let desc = '';
    if (kind === 0) {
      const local = index - importedFuncs;
      desc = local >= 0 ? types[funcTypeIdx[local]] : imports.filter((i) => i.kind === 'func')[index].desc;
    }
    return { name, kind: KIND[kind], desc };
  });
  imports.sort((a, b) => `${a.module}\0${a.name}`.localeCompare(`${b.module}\0${b.name}`));
  exports.sort((a, b) => a.name.localeCompare(b.name));
  return {
    imports,
    exports,
    functions: importedFuncs + funcTypeIdx.length,
    definedFunctions: funcTypeIdx.length,
    codeEntries: codeCount,
    memories,
    tables,
    globalImports: globals,
    dataCount,
    hasStart,
  };
}

/** Same description with entries that depend on the code size removed. */
export function abiOf(bytes) {
  const d = describeWasm(bytes);
  // The number of defined functions, data segments, initial memory pages and
  // table sizes move with the size of the code and of the embedded strings
  // (which include build paths); only the boundary is compared.
  const noSize = (limits) => limits.replace(/^\d+\.\.\d*/, '');
  return {
    imports: d.imports,
    exports: d.exports,
    memories: d.memories.map(noSize),
    tables: d.tables.map((t) => t.split(' ')[0]),
    hasStart: d.hasStart,
  };
}
