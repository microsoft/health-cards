/* eslint-disable @typescript-eslint/no-explicit-any */
import { Option, Command } from 'commander';
import fs from 'fs';
import got from 'got';
import jose, { JWK } from 'node-jose';
import pako, { deflate, deflateRaw } from 'pako';
import QrCode, { QRCodeSegment } from 'qrcode';


const ISSUER_URL = process.env.ISSUER_URL || 'https://smarthealth.cards/examples/issuer' ;

const exampleBundleUrls = [
  'http://build.fhir.org/ig/dvci/vaccine-credential-ig/branches/main/Bundle-Scenario1Bundle.json',
  'http://build.fhir.org/ig/dvci/vaccine-credential-ig/branches/main/Bundle-Scenario2Bundle.json',
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
  iat: number;
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

  async signJws(idTokenPayload: Record<string, unknown>, deflate = true): Promise<string> {
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
      }
      if (r.coding) {
        delete r.text;
      }
      // Address bug in hosted examples
      if (r.system === 'https://phinvads.cdc.gov/vads/ViewCodeSystem.action?id=2.16.840.1.113883.12.292') {
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

function createHealthCardJwsPayload(fhirBundle: Bundle): Record<string, unknown> {
  return {
    iss: ISSUER_URL + _issuerUrlSuffix,
    iat: new Date().getTime() / 1000, // TODO: add not yet valid
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: [
        'VerifiableCredential',
        _healthCardUri,
        'https://smarthealth.cards#immunization',
        'https://smarthealth.cards#covid19',
      ],
      credentialSubject: {
        fhirVersion: '4.0.1', // TODO: which fhirVersion is ok?
        fhirBundle,
      },
    },
  };
}

async function createHealthCardFile(jwsPayload: Record<string, unknown>): Promise<Record<string, any>> {
  const signer = new Signer({ signingKey: await JWK.asKey(_issuerSigningKey) });
  const signed = await signer.signJws(jwsPayload);
  return {
    verifiableCredential: [signed],
  };
}

const SMALLEST_B64_CHAR_CODE = 45; // "-".charCodeAt(0) === 45
const toNumericQr = (jws: string): QRCodeSegment[] => [
  { data: _qrHeader, mode: 'byte' },
  {
    data: jws
      .split('')
      .map((c) => c.charCodeAt(0) - SMALLEST_B64_CHAR_CODE)
      .flatMap((c) => [Math.floor(c / 10), c % 10])
      .join(''),
    mode: _qrMode,
  },
];

async function processExampleBundle(exampleBundleUrl: string) {
  const exampleBundleRetrieved = (await got(exampleBundleUrl).json()) as Bundle;
  const exampleBundleTrimmedForHealthCard = await trimBundleForHealthCard(exampleBundleRetrieved);
  const exampleJwsPayload = createHealthCardJwsPayload(exampleBundleTrimmedForHealthCard);
  const exampleBundleHealthCardFile = await createHealthCardFile(exampleJwsPayload);

  const qrSegments = toNumericQr(exampleBundleHealthCardFile.verifiableCredential[0]);
  const exampleBundleHealthCardNumericQr = qrSegments.map(({ data }) => data).join('');

  const exampleQrCode: string = await new Promise((resolve, reject) =>
    QrCode.toString(qrSegments, { type: 'svg' }, function (err: any, result: string) {
      if (err) return reject(err);
      resolve(result as string);
    }),
  );

  return {
    fhirBundle: exampleBundleTrimmedForHealthCard,
    payload: exampleJwsPayload,
    file: exampleBundleHealthCardFile,
    qrNumeric: exampleBundleHealthCardNumericQr,
    qrSvg: exampleQrCode,
  };
}

async function generate(options: { outdir: string, testcase:string }) {
  const exampleIndex: string[][] = [];
  const writeExamples = exampleBundleUrls.map(async (url, i) => {
    const exNum = i.toLocaleString('en-US', {
      minimumIntegerDigits: 2,
      useGrouping: false,
    });
    const outputPrefix = `example-${exNum}-`;
    const ouputSuffix = options.testcase ? `-${options.testcase}` : '';
    const example = await processExampleBundle(url);
    const fileA = `${outputPrefix}a-fhirBundle${ouputSuffix}.json`;
    const fileB = `${outputPrefix}b-jws-payload-expanded${ouputSuffix}.json`;
    const fileC = `${outputPrefix}c-jws-payload-minified${ouputSuffix}.json`;
    const fileD = `${outputPrefix}d-jws${ouputSuffix}.txt`;
    const fileE = `${outputPrefix}e-file${ouputSuffix}.smart-health-card`;
    const fileF = `${outputPrefix}f-qr-code-numeric${ouputSuffix}.txt`;
    const fileG = `${outputPrefix}g-qr-code${ouputSuffix}.svg`;

    fs.writeFileSync(`${options.outdir}/${fileA}`, JSON.stringify(example.fhirBundle, null, 2));
    fs.writeFileSync(`${options.outdir}/${fileB}`, JSON.stringify(example.payload, null, 2));
    fs.writeFileSync(`${options.outdir}/${fileC}`, JSON.stringify(example.payload));
    fs.writeFileSync(`${options.outdir}/${fileD}`, example.file.verifiableCredential[0]);
    fs.writeFileSync(`${options.outdir}/${fileE}`, JSON.stringify(example.file, null, 2));
    fs.writeFileSync(`${options.outdir}/${fileF}`, example.qrNumeric);
    fs.writeFileSync(`${options.outdir}/${fileG}`, example.qrSvg);

    const exampleEntry: string[] = [];
    exampleEntry.push(fileA);
    exampleEntry.push(fileB);
    exampleEntry.push(fileC);
    exampleEntry.push(fileD);
    exampleEntry.push(fileE);
    exampleEntry.push(fileF);
    exampleEntry.push(fileG);
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
  'invalid_deflate',
  'invalid_jws_format',
  'invalid_issuer_url',
  'wrong_qr_header',
  'wrong_qr_mode',
  'wrong_issuer_key',
  'wrong_issuer_curve_key',
  'wrong_issuer_kid_key',
  'wrong_issuer_kty_key',
  'invalid_healthcard_uri'
]));
program.parse(process.argv);

interface Options {
  outdir: string;
  testcase: string;
}

const options = program.opts() as Options;
console.log('Opts', options);

// Test case options
const _deflateFunction = options.testcase == 'invalid_deflate' ? pako.deflateRaw : pako.deflate;
const _jwsFormat = options.testcase == 'invalid_jws_format' ? 'flattened' : 'compact';
const _issuerUrlSuffix = options.testcase == 'invalid_issuer_url' ? 'invalid_url' : '';
const _qrHeader = options.testcase == 'wrong_qr_header' ? 'shc:' : 'shc:/';
const _qrMode = options.testcase == 'wrong_qr_mode' ? 'byte' : 'numeric';
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

