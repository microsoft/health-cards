/* eslint-disable @typescript-eslint/no-explicit-any */
import { Option, Command } from 'commander';
import fs from 'fs';
import got from 'got';
import jose, { JWK } from 'node-jose';
import pako, { deflate, deflateRaw } from 'pako';
import QrCode, { QRCodeSegment } from 'qrcode';


const ISSUER_URL = process.env.ISSUER_URL || 'smarthealth.cards/examples/issuer' ;

interface BundleInfo {
  url: string;
  issuerIndex: number;
}

const exampleBundleInfo: BundleInfo[] = [
  {url: 'https://raw.githubusercontent.com/dvci/vaccine-credential-ig/main/examples/Scenario1Bundle.json', issuerIndex: 0},
  {url: 'https://raw.githubusercontent.com/dvci/vaccine-credential-ig/main/examples/Scenario2Bundle.json', issuerIndex: 2},
  {url: 'https://www.hl7.org/fhir/diagnosticreport-example-ghp.json', issuerIndex: 0}
];

interface Bundle {
  id?: string;
  meta?: Record<string, unknown>;
  entry: {
    fullUrl: string;
    resource: {
      meta?: Record<string, unknown>;
      id?: string;
      [k: string]: unknown;
    };
  }[];
}

interface StringMap {
  [k: string]: string;
}

export interface HealthCard {
  iss: string;
  nbf: number;
  exp: number;
  vc: {
    type: string[];
    credentialSubject: {
      fhirVersion: string;
      fhirBundle: Record<string, unknown>;
    };
  };
}

export class Signer {
  public keyStore: jose.JWK.KeyStore;
  public signingKey: JWK.Key;

  constructor({ keyStore, signingKey }: { signingKey: JWK.Key; keyStore?: JWK.KeyStore }) {
    this.keyStore = keyStore || jose.JWK.createKeyStore();
    this.signingKey = signingKey;
  }

  async signJws(idTokenPayload: Record<string, unknown>, deflate = _doDeflate): Promise<string> {
    const bodyString = JSON.stringify(idTokenPayload);

    const fields = deflate ? { zip: 'DEF' } : {};
    const body = deflate ? _deflateFunction(bodyString) : bodyString;

    const signed = await jose.JWS.createSign({ format: _jwsFormat, fields }, this.signingKey)
      .update(Buffer.from(body))
      .final();
    return (signed as unknown) as string;
  }
}

async function trimBundleForHealthCard(bundleIn: Bundle) {
  const bundle: Bundle = JSON.parse(JSON.stringify(bundleIn)) as Bundle;
  delete bundle.id;
  delete bundle.meta;

  const resourceUrlMap: StringMap = bundle.entry
    .map((e, i) => [e.fullUrl.split('/').slice(-2).join('/'), `resource:${i}`])
    .reduce((acc: StringMap, [a, b]) => {
      acc[a] = b;
      return acc;
    }, {});

  delete bundle.id;
  bundle.entry.forEach((e) => {
    e.fullUrl = resourceUrlMap[e.fullUrl.split('/').slice(-2).join('/')];
    function clean(r: any, path: string[] = ['Resource']) {

      if (r.resourceType === 'Patient') {
        // TODO remove these `delete`s once sample bundles are aligned
        // with the "name + DOB" profiling guidance
        delete r.telecom;
        delete r.communication;
        delete r.address;
      }

      if (path.length === 1) {
        delete r.id;
        delete r.meta;
        delete r.text;
      }
      if (resourceUrlMap[r.reference]) {
        r.reference = resourceUrlMap[r.reference];
      } else if (r?.reference?.startsWith("Patient")) {
        //TODO remove this branch when DVCI bundles are fixed
        r.reference = 'resource:0'
      }
      if (r.coding) {
        delete r.text;
      }
      if (r.system === 'http://hl7.org/fhir/sid/cvx-TEMPORARY-CODE-SYSTEM') {
        r.system = 'http://hl7.org/fhir/sid/cvx';
      }
      if (r.system && r.code) {
        delete r.display;
      }
      if (Array.isArray(r)) {
        r.forEach((e) => clean(e, path));
      } else if (r !== null && typeof r === 'object') {
        Object.keys(r).forEach((k) => clean(r[k], [...path, k]));
      }
    }
    clean(e.resource);
  });

  return bundle;
}

function createHealthCardJwsPayload(fhirBundle: Bundle, types: string[]): Record<string, unknown> {
  return {
    iss: _issuerUrlPrefix + ISSUER_URL + _issuerUrlSuffix + _issuerUrlSuffix2,
    nbf: new Date().getTime() / _nbfDivisor,
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: [
        'VerifiableCredential',
        'https://smarthealth.cards#immunization',
        'https://smarthealth.cards#covid19',
        _healthCardUri,
        ...types
      ],
      credentialSubject: {
        fhirVersion: '4.0.1', // TODO: which fhirVersion is ok?
        fhirBundle,
      },
    },
  };
}

const MAX_SINGLE_JWS_SIZE = 1195;
const MAX_CHUNK_SIZE = 1191;
const splitJwsIntoChunks = (jws: string): string[] => {
  if (jws.length <= _MAX_SINGLE_JWS_SIZE) {
    return [jws];
  }

  // Try to split the chunks into roughly equal sizes.
  const chunkCount = Math.ceil(jws.length / _MAX_CHUNK_SIZE);
  const chunkSize = Math.ceil(jws.length / chunkCount);
  const chunks = jws.match(new RegExp(`.{1,${chunkSize}}`, 'g'));
  return chunks || [];
}

async function createHealthCardFile(jwsPayload: Record<string, unknown>, keyIndex: number = 0): Promise<Record<string, any>> {
  const signer = new Signer({ signingKey: await JWK.asKey(_issuerSigningKey.keys[keyIndex]) });
  const signed = await signer.signJws(jwsPayload);
  return {
    verifiableCredential: [signed],
  };
}

const SMALLEST_B64_CHAR_CODE = 45; // "-".charCodeAt(0) === 45
const toNumericQr = (jws: string, chunkIndex: number, totalChunks: number): QRCodeSegment[] => [
  { data: _qrHeader + ((totalChunks > 1) ? `${chunkIndex + 1}/${totalChunks}/` : ``), mode: 'byte' },
  {
    data: jws
      .split('')
      .map((c) => c.charCodeAt(0) - SMALLEST_B64_CHAR_CODE)
      .flatMap((c) => [Math.floor(c / 10), c % 10])
      .join(''),
    mode: _qrMode,
  },
];

async function processExampleBundle(exampleBundleInfo: BundleInfo): Promise<{ fhirBundle: Bundle; payload: Record<string, unknown>; file: Record<string, any>; qrNumeric: string[]; qrSvgFiles: string[]; }> {
  let types = exampleBundleInfo.url.match("vaccine") ? [
    'https://smarthealth.cards#immunization',
    'https://smarthealth.cards#covid19',
  ] : [];

  const exampleBundleRetrieved = (await got(exampleBundleInfo.url).json()) as Bundle;
  const exampleBundleTrimmedForHealthCard = await trimBundleForHealthCard(exampleBundleRetrieved);
  const exampleJwsPayload = createHealthCardJwsPayload(exampleBundleTrimmedForHealthCard, types);
  const exampleBundleHealthCardFile = await createHealthCardFile(exampleJwsPayload, exampleBundleInfo.issuerIndex);

  const jws = exampleBundleHealthCardFile.verifiableCredential[0] as string;
  const jwsChunks = splitJwsIntoChunks(jws);
  const qrSet = jwsChunks.map((c, i, chunks) => toNumericQr(c, i, chunks.length));
  const exampleBundleHealthCardNumericQr = qrSet.map(qr => qr.map(({ data }) => data).join(''));

  const exampleQrCodes: string[] = await Promise.all(
    qrSet.map((qrSegments): Promise<string> => new Promise((resolve, reject) =>
      QrCode.toString(qrSegments, { type: 'svg', errorCorrectionLevel: 'low' }, function (err: any, result: string) {
        if (err) return reject(err);
        resolve(result as string);
      })
    )));

  return {
    fhirBundle: exampleBundleTrimmedForHealthCard,
    payload: exampleJwsPayload,
    file: exampleBundleHealthCardFile,
    qrNumeric: exampleBundleHealthCardNumericQr,
    qrSvgFiles: exampleQrCodes,
  };
}

async function generate(options: { outdir: string, testcase:string }) {
  const exampleIndex: string[][] = [];
  const writeExamples = exampleBundleInfo.map(async (info, i) => {
    const exNum = i.toLocaleString('en-US', {
      minimumIntegerDigits: 2,
      useGrouping: false,
    });
    const outputPrefix = _OUTPUT_PREFIX + `example-${exNum}-`;
    const ouputSuffix = options.testcase ? `-${options.testcase}` : '';
    const example = await processExampleBundle(info);
    const fileA = `${outputPrefix}a-fhirBundle${ouputSuffix}.json`;
    const fileB = `${outputPrefix}b-jws-payload-expanded${ouputSuffix}.json`;
    const fileC = `${outputPrefix}c-jws-payload-minified${ouputSuffix}.json`;
    const fileD = `${outputPrefix}d-jws${ouputSuffix}.txt`;
    const fileE = `${outputPrefix}e-file${ouputSuffix}.smart-health-card`;

    const fileF = example.qrNumeric.map((qr, i) => `${outputPrefix}f-qr-code-numeric-value-${i}${ouputSuffix}.txt`);
    const fileG = example.qrSvgFiles.map((qr, i) => `${outputPrefix}g-qr-code-${i}${ouputSuffix}.svg`);

    fs.writeFileSync(`${options.outdir}/${fileA}`, _TRAILING_CHARS + JSON.stringify(example.fhirBundle, null, 2) + _TRAILING_CHARS);
    fs.writeFileSync(`${options.outdir}/${fileB}`, _TRAILING_CHARS + JSON.stringify(example.payload, null, 2) + _TRAILING_CHARS);
    fs.writeFileSync(`${options.outdir}/${fileC}`, _TRAILING_CHARS + JSON.stringify(example.payload) + _TRAILING_CHARS);
    fs.writeFileSync(`${options.outdir}/${fileD}`, _TRAILING_CHARS + example.file.verifiableCredential[0] + _TRAILING_CHARS);
    fs.writeFileSync(`${options.outdir}/${fileE}`, _TRAILING_CHARS + JSON.stringify(example.file, null, 2) + _TRAILING_CHARS);
    example.qrNumeric.forEach((qr, i) => {
      fs.writeFileSync(`${options.outdir}/${fileF[i]}`, _TRAILING_CHARS + qr + _TRAILING_CHARS);
    });

    example.qrSvgFiles.forEach((qr, i) => {
      fs.writeFileSync(`${options.outdir}/${fileG[i]}`, qr);
    });

    const exampleEntry: string[] = [];

    exampleEntry.push(fileA);
    exampleEntry.push(fileB);
    exampleEntry.push(fileC);
    exampleEntry.push(fileD);
    exampleEntry.push(fileE);
    fileF.forEach(f => exampleEntry.push(f))
    fileG.forEach(f => exampleEntry.push(f))
    exampleIndex[i] = exampleEntry;
  });

  await Promise.all(writeExamples);
  fs.writeFileSync(
    `${options.outdir}/index.md`,
    '# Example Resources \n' +
    exampleIndex.map((e, i) => `## Example ${i}\n\n` + e.map((f) => `* [${f}](./${f})`).join('\n')).join('\n\n'),
  );
}

const program = new Command();
program.option('-o, --outdir <outdir>', 'output directory');
program.addOption(new Option('-t, --testcase <testcase>', 'test case to generate').choices([
  'no_deflate',
  'invalid_deflate',
  'invalid_jws_format',
  'invalid_issuer_url',
  'issuer_url_with_trailing_slash',
  'invalid_issuer_url_http',
  'wrong_qr_header',
  'wrong_qr_mode',
  'wrong_issuer_key',
  'wrong_issuer_curve_key',
  'wrong_issuer_kid_key',
  'wrong_issuer_kty_key',
  'invalid_healthcard_uri',
  'qr_chunk_too_big',
  'qr_chunk_unbalanced', // TODO
  'trailing_chars',
  'nbf_miliseconds'
]));
program.parse(process.argv);

interface Options {
  outdir: string;
  testcase: string;
}

const options = program.opts() as Options;
console.log('Opts', options);

// Test case options
const _OUTPUT_PREFIX = options.testcase ? 'test-' : '';
const _TRAILING_CHARS = options.testcase == 'trailing_chars' ? ' \t\n ' : '';
const _MAX_SINGLE_JWS_SIZE = options.testcase == 'qr_chunk_too_big' ? 2500 : MAX_SINGLE_JWS_SIZE;
const _MAX_CHUNK_SIZE = _MAX_SINGLE_JWS_SIZE - 4;
const _doDeflate = options.testcase == 'no_deflate' ? false : true;
const _deflateFunction = options.testcase == 'invalid_deflate' ? pako.deflate : pako.deflateRaw;
const _jwsFormat = options.testcase == 'invalid_jws_format' ? 'flattened' : 'compact';
const _issuerUrlPrefix = options.testcase == 'invalid_issuer_url_http' ? 'http://' : 'https://';
const _issuerUrlSuffix = options.testcase == 'invalid_issuer_url' ? 'invalid_url' : '';
const _issuerUrlSuffix2 = options.testcase == 'issuer_url_with_trailing_slash' ? '/' : '';
const _qrHeader = options.testcase == 'wrong_qr_header' ? 'shc:' : 'shc:/';
const _qrMode = options.testcase == 'wrong_qr_mode' ? 'byte' : 'numeric';
const _nbfDivisor = options.testcase == 'nbf_miliseconds' ? 1 : 1000;
const _issuerKeyFile = './src/config/' + 
  (options.testcase == 'wrong_issuer_key' ? 'issuer2.jwks.private.json' : 
    (options.testcase == 'wrong_issuer_curve_key' ? 'issuer_wrong_curve.jwks.private.json' : 
      (options.testcase == 'wrong_issuer_kid_key' ? 'issuer_wrong_kid.jwks.private.json' : 
        (options.testcase == 'wrong_issuer_kty_key' ? 'issuer_wrong_kty.jwks.private.json' :
          'issuer.jwks.private.json'))));
const _issuerSigningKey = JSON.parse(fs.readFileSync(_issuerKeyFile, 'utf-8'));
const _healthCardUri = options.testcase == 'invalid_healthcard_uri' ? 'https://smarthealth.cards#health-card' : 'https://smarthealth.cards#wrong-health-card';

if (options.outdir) {
  generate(options);
}

