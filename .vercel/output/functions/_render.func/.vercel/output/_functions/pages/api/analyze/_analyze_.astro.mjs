import { c as createComponent, e as createAstro } from '../../../chunks/astro/server_luQAfNtd.mjs';
import 'kleur/colors';
import 'clsx';
export { renderers } from '../../../renderers.mjs';

const API_VT_IP = "https://www.virustotal.com/api/v3/ip_addresses";
const API_ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check?ipAddress";
async function analyzeIP(ip) {
  const virustotalKey = "7f14b7b5ffc3f4eb0210680089289014119dfc012c9e9e35618537fc3ed2b589";
  const abuseipdbKey = "0a9c31011f3c300938fd074d3e66a04f1500b9dc6dfec55bd66385c4ecf9ed870817cb24da25fcf5";
  const urlVTIPInfo = `${API_VT_IP}/${ip}`;
  const virustotalResponse = await fetch(urlVTIPInfo, {
    headers: {
      "x-apikey": virustotalKey
    }
  });
  const urlAbuseIPDBInfo = `${API_ABUSEIPDB}=${ip}`;
  const abuseipdbResponse = await fetch(urlAbuseIPDBInfo, {
    headers: {
      "Key": abuseipdbKey,
      "Accept": "application/json"
    }
  });
  const virustotalData = await virustotalResponse.json();
  const abuseipdbData = await abuseipdbResponse.json();
  return {
    virustotal: virustotalData,
    abuseipdb: abuseipdbData
  };
}

const API_VT_DOMAIN = "https://www.virustotal.com/api/v3/domains";
const API_OTX_DOMAIN = "https://otx.alienvault.com/api/v1/indicators/domain";
async function analyzeDomain(domain) {
  const virustotalKey = "7f14b7b5ffc3f4eb0210680089289014119dfc012c9e9e35618537fc3ed2b589";
  const otxKey = "ffa8e3ed8bf53bc083cb5038b86ed53118c92b02981c036eb99817c76c68ee17";
  const urlVTDomainInfo = `${API_VT_DOMAIN}/${domain}`;
  const virustotalResponse = await fetch(urlVTDomainInfo, {
    headers: {
      "x-apikey": virustotalKey
    }
  });
  const urlOTXDomainInfo = `${API_OTX_DOMAIN}/${domain}/general`;
  const otxResponse = await fetch(urlOTXDomainInfo, {
    headers: {
      "X-OTX-API-KEY": otxKey
    }
  });
  const virustotalData = await virustotalResponse.json();
  const otxData = await otxResponse.json();
  return {
    virustotal: virustotalData,
    otx: otxData
  };
}

async function analyzeEmail(email) {
  return {
    emailrep: `Not implemented yet ${email}`,
    haveibeenpwned: `Not implemented yet ${email}`
  };
}

const API_VT_FILEHASH = "https://www.virustotal.com/api/v3/files";
const API_POLYSWARM = "https://api.polyswarm.network/v3/search/hash";
function checkHashType(hash) {
  if (/^[a-f0-9]{32}$/i.test(hash)) {
    return "md5";
  }
  if (/^[a-f0-9]{40}$/i.test(hash)) {
    return "sha1";
  }
  if (/^[a-f0-9]{64}$/i.test(hash)) {
    return "sha256";
  }
  return "N/A";
}
async function analyzeHash(hash) {
  const virustotalKey = "7f14b7b5ffc3f4eb0210680089289014119dfc012c9e9e35618537fc3ed2b589";
  const polyswarmKey = "4fe87b6744b162377c8a65bec5b7e5c8";
  const urlVTFilehashInfo = `${API_VT_FILEHASH}/${hash}`;
  const virustotalResponse = await fetch(urlVTFilehashInfo, {
    headers: {
      "x-apikey": virustotalKey
    }
  });
  const hashType = checkHashType(hash);
  const urlPolyswarmInfo = `${API_POLYSWARM}/${hashType}?hash=${hash}`;
  const polyswarmResponse = await fetch(urlPolyswarmInfo, {
    headers: {
      "Authorization": `${polyswarmKey}`
    }
  });
  const virustotalData = await virustotalResponse.json();
  const polyswarmData = await polyswarmResponse.json();
  console.log(virustotalData);
  console.log(polyswarmData);
  return {
    /*virustotal: virustotalData,*/
    /*polyswarm: polyswarmData,*/
  };
}

const $$Astro = createAstro();
const prerender = false;
const $$analyze = createComponent(async ($$result, $$props, $$slots) => {
  const Astro2 = $$result.createAstro($$Astro, $$props, $$slots);
  Astro2.self = $$analyze;
  const { analyze } = Astro2.params;
  const ioc = Astro2.url.searchParams.get("ioc");
  if (!ioc) {
    return new Response(JSON.stringify({ error: "Missing IoC parameter" }), {
      status: 400
    });
  }
  let result;
  switch (analyze) {
    case "ip":
      result = await analyzeIP(ioc);
      break;
    case "domain":
      result = await analyzeDomain(ioc);
      break;
    case "email":
      result = await analyzeEmail(ioc);
      break;
    case "hash":
      result = await analyzeHash(ioc);
      break;
    default:
      return new Response(
        JSON.stringify({ error: "Invalid analysis type" }),
        { status: 400 }
      );
  }
  return new Response(JSON.stringify(result));
}, "/home/mpat/experimento/iocdb-share/src/pages/api/analyze/[analyze].astro", void 0);

const $$file = "/home/mpat/experimento/iocdb-share/src/pages/api/analyze/[analyze].astro";
const $$url = "/api/analyze/[analyze]";

const _page = /*#__PURE__*/Object.freeze(/*#__PURE__*/Object.defineProperty({
    __proto__: null,
    default: $$analyze,
    file: $$file,
    prerender,
    url: $$url
}, Symbol.toStringTag, { value: 'Module' }));

const page = () => _page;

export { page };
