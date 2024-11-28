import { c as createComponent, e as createAstro } from '../../../chunks/astro/server_luQAfNtd.mjs';
import 'kleur/colors';
import 'clsx';
export { renderers } from '../../../renderers.mjs';

const API_VT_IP = "https://www.virustotal.com/api/v3/ip_addresses";
const API_ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check?ipAddress";
async function analyzeIP(ip) {
  const virustotalKey = undefined                                  ;
  const abuseipdbKey = undefined                                 ;
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
    virustotal: {
      malicious: virustotalData.data.attributes.last_analysis_stats.malicious,
      suspicious: virustotalData.data.attributes.last_analysis_stats.suspicious
    },
    abuseipdb: {
      country: abuseipdbData.data.countryCode,
      isp: abuseipdbData.data.isp
    }
  };
}

const API_VT_DOMAIN = "https://www.virustotal.com/api/v3/domains";
const API_OTX_DOMAIN = "https://otx.alienvault.com/api/v1/indicators/domain";
async function analyzeDomain(domain) {
  const virustotalKey = undefined                                  ;
  const otxKey = undefined                           ;
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
    virustotal: {
      malicious: virustotalData.data.attributes.last_analysis_stats.malicious,
      suspicious: virustotalData.data.attributes.last_analysis_stats.suspicious
    },
    otx: {
      pulseCount: otxData.pulse_info.count
    }
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
  const virustotalKey = undefined                                  ;
  const polyswarmKey = undefined                                 ;
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
    /*virustotal: {
        malicious: virustotalData.data.attributes.last_analysis_stats.malicious,
        suspicious: virustotalData.data.attributes.last_analysis_stats.suspicious,
    },*/
    /*filescan: {
        threatLevel: filescanData.scan_results.threat_level,
        threatNames: filescanData.scan_results.threat_names,
    },*/
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
