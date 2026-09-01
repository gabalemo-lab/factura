/**
 * ARCA / AFIP Web Service Bridge Server
 * Conector Oficial Autónomo para Facturación Electrónica en Argentina (WSAA + WSFEv1)
 *
 * Ejecución:
 *   node arca-server.js
 *   (Puerto por defecto: 3000 o process.env.PORT)
 */

const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const PORT = process.env.PORT || 3000;
const CONFIG_FILE = path.join(__dirname, "arca-config.json");

// Configuración por defecto
let arcaConfig = {
  cuit: "20123456789",
  entorno: "homologacion", // "homologacion" o "produccion"
  puntoVenta: 2,
  certPath: path.join(__dirname, "certificado.crt"),
  keyPath: path.join(__dirname, "privada.key"),
  certContent: "",
  keyContent: "",
};

if (fs.existsSync(CONFIG_FILE)) {
  try {
    arcaConfig = { ...arcaConfig, ...JSON.parse(fs.readFileSync(CONFIG_FILE, "utf-8")) };
  } catch (e) {
    console.warn("No se pudo cargar arca-config.json, usando defaults");
  }
}

// Variables de entorno para despliegue en la nube (Render, Railway, VPS)
if (process.env.ARCA_CUIT) arcaConfig.cuit = process.env.ARCA_CUIT;
if (process.env.ARCA_MODO) arcaConfig.entorno = process.env.ARCA_MODO;
if (process.env.ARCA_PV) arcaConfig.puntoVenta = Number(process.env.ARCA_PV);
if (process.env.ARCA_CERT) arcaConfig.certContent = process.env.ARCA_CERT;
if (process.env.ARCA_KEY) arcaConfig.keyContent = process.env.ARCA_KEY;

// Caché de Ticket de Acceso (WSAA)
let authTicketCache = {
  token: null,
  sign: null,
  expiration: null,
};

function getUrls() {
  const isProd = arcaConfig.entorno === "produccion";
  return {
    wsaa: isProd
      ? "https://wsaa.afip.gov.ar/ws/services/LoginCms"
      : "https://wsaahomo.afip.gov.ar/ws/services/LoginCms",
    wsfe: isProd
      ? "https://servicios1.afip.gov.ar/wsfev1/service.asmx"
      : "https://wswhomo.afip.gov.ar/wsfev1/service.asmx",
  };
}

/**
 * Genera el XML TRA (Ticket de Requerimiento de Acceso)
 */
function createTraXml(service = "wsfe") {
  const now = new Date();
  const genTime = new Date(now.getTime() - 10 * 60 * 1000).toISOString();
  const expTime = new Date(now.getTime() + 10 * 60 * 1000).toISOString();
  const uniqueId = Math.floor(Date.now() / 1000);

  return `<?xml version="1.0" encoding="UTF-8"?>
<loginTicketRequest version="1.0">
  <header>
    <uniqueId>${uniqueId}</uniqueId>
    <generationTime>${genTime}</generationTime>
    <expirationTime>${expTime}</expirationTime>
  </header>
  <service>${service}</service>
</loginTicketRequest>`;
}

/**
 * Firma el TRA con CMS / PKCS#7 usando certificado y clave privada
 */
function signTra(traXml) {
  const tmpTra = path.join("/tmp", `tra_${Date.now()}.xml`);
  const tmpCms = path.join("/tmp", `tra_${Date.now()}.cms`);
  const tmpCert = path.join("/tmp", `cert_${Date.now()}.crt`);
  const tmpKey = path.join("/tmp", `key_${Date.now()}.key`);

  try {
    fs.writeFileSync(tmpTra, traXml, "utf-8");

    let certFile = arcaConfig.certPath;
    let keyFile = arcaConfig.keyPath;

    if (arcaConfig.certContent) {
      fs.writeFileSync(tmpCert, arcaConfig.certContent, "utf-8");
      certFile = tmpCert;
    }
    if (arcaConfig.keyContent) {
      fs.writeFileSync(tmpKey, arcaConfig.keyContent, "utf-8");
      keyFile = tmpKey;
    }

    if (!fs.existsSync(certFile) || !fs.existsSync(keyFile)) {
      throw new Error(`Certificado o clave no encontrados (${certFile}, ${keyFile}). Cargalos en Configuración.`);
    }

    // Firma PKCS#7 en formato DER
    execSync(`openssl cms -sign -in "${tmpTra}" -out "${tmpCms}" -signer "${certFile}" -inkey "${keyFile}" -outform DER -nodetach`);
    const cmsDer = fs.readFileSync(tmpCms);
    return cmsDer.toString("base64");
  } finally {
    try { if (fs.existsSync(tmpTra)) fs.unlinkSync(tmpTra); } catch (_) {}
    try { if (fs.existsSync(tmpCms)) fs.unlinkSync(tmpCms); } catch (_) {}
    try { if (fs.existsSync(tmpCert)) fs.unlinkSync(tmpCert); } catch (_) {}
    try { if (fs.existsSync(tmpKey)) fs.unlinkSync(tmpKey); } catch (_) {}
  }
}

/**
 * Realiza un POST SOAP seguro
 */
function postSoap(urlStr, soapAction, soapBody) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const headers = {
      "Content-Type": "text/xml; charset=utf-8",
      "Content-Length": Buffer.byteLength(soapBody),
      SOAPAction: soapAction,
    };

    const req = https.request(
      {
        hostname: u.hostname,
        port: u.port || 443,
        path: u.pathname,
        method: "POST",
        headers,
      },
      (res) => {
        let raw = "";
        res.on("data", (chunk) => (raw += chunk));
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(raw);
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${raw}`));
          }
        });
      }
    );

    req.on("error", (e) => reject(e));
    req.write(soapBody);
    req.end();
  });
}

/**
 * Obtiene el Ticket de Acceso (Token + Sign) desde WSAA con caché
 */
async function getAuthTicket() {
  const now = new Date();
  if (authTicketCache.token && authTicketCache.expiration && authTicketCache.expiration > now) {
    return authTicketCache;
  }

  const urls = getUrls();
  const tra = createTraXml("wsfe");
  const cmsBase64 = signTra(tra);

  const soap = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsaa="http://wsaa.view.sua.dvadac.desein.afip.gov">
  <soapenv:Header/>
  <soapenv:Body>
    <wsaa:loginCms>
      <wsaa:in0>${cmsBase64}</wsaa:in0>
    </wsaa:loginCms>
  </soapenv:Body>
</soapenv:Envelope>`;

  const respXml = await postSoap(urls.wsaa, "", soap);
  const tokenMatch = respXml.match(/<token>(.*?)<\/token>/);
  const signMatch = respXml.match(/<sign>(.*?)<\/sign>/);
  const expMatch = respXml.match(/<expirationTime>(.*?)<\/expirationTime>/);

  if (!tokenMatch || !signMatch) {
    const faultMatch = respXml.match(/<faultstring>(.*?)<\/faultstring>/);
    throw new Error(faultMatch ? faultMatch[1] : "Error obteniendo autorización de ARCA / AFIP (WSAA).");
  }

  const token = tokenMatch[1];
  const sign = signMatch[1];
  const expDate = expMatch ? new Date(expMatch[1]) : new Date(now.getTime() + 10 * 3600 * 1000);

  authTicketCache = {
    token,
    sign,
    expiration: expDate,
  };

  return authTicketCache;
}

/**
 * Consulta el estado de los servidores de AFIP (FEDummy)
 */
async function getStatus() {
  const urls = getUrls();
  const soap = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <FEDummy xmlns="http://ar.gov.afip.dif.FEV1/" />
  </soap:Body>
</soap:Envelope>`;

  try {
    const resp = await postSoap(urls.wsfe, "http://ar.gov.afip.dif.FEV1/FEDummy", soap);
    const app = (resp.match(/<AppServer>(.*?)<\/AppServer>/) || [])[1] || "—";
    const db = (resp.match(/<DbServer>(.*?)<\/DbServer>/) || [])[1] || "—";
    const auth = (resp.match(/<AuthServer>(.*?)<\/AuthServer>/) || [])[1] || "—";
    return {
      online: app === "OK" && db === "OK" && auth === "OK",
      appServer: app,
      dbServer: db,
      authServer: auth,
      entorno: arcaConfig.entorno,
      cuit: arcaConfig.cuit,
      puntoVenta: arcaConfig.puntoVenta,
    };
  } catch (err) {
    return {
      online: false,
      error: err.message,
      entorno: arcaConfig.entorno,
    };
  }
}

/**
 * Consulta el último comprobante autorizado en AFIP (FECompUltimoAutorizado)
 */
async function getUltimoComprobante(ptoVta, cbteTipo) {
  const auth = await getAuthTicket();
  const urls = getUrls();
  const cuit = Number(String(arcaConfig.cuit).replace(/\D/g, ""));

  const soap = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <FECompUltimoAutorizado xmlns="http://ar.gov.afip.dif.FEV1/">
      <Auth>
        <Token>${auth.token}</Token>
        <Sign>${auth.sign}</Sign>
        <Cuit>${cuit}</Cuit>
      </Auth>
      <PtoVta>${Number(ptoVta)}</PtoVta>
      <CbteTipo>${Number(cbteTipo)}</CbteTipo>
    </FECompUltimoAutorizado>
  </soap:Body>
</soap:Envelope>`;

  const resp = await postSoap(urls.wsfe, "http://ar.gov.afip.dif.FEV1/FECompUltimoAutorizado", soap);
  const nroMatch = resp.match(/<CbteNro>(\d+)<\/CbteNro>/);
  if (!nroMatch) {
    const errMatch = resp.match(/<Msg>(.*?)<\/Msg>/);
    throw new Error(errMatch ? errMatch[1] : "Error consultando último comprobante en ARCA.");
  }

  const nro = parseInt(nroMatch[1], 10);
  return { ultimoNumero: nro, proximoNumero: nro + 1 };
}

/**
 * Solicita CAE para un comprobante en AFIP (FECAESolicitar)
 */
async function emitirFacturaArca(datos) {
  const auth = await getAuthTicket();
  const urls = getUrls();
  const cuitEmisor = Number(String(arcaConfig.cuit).replace(/\D/g, ""));

  const ptoVta = Number(datos.ptoVta || arcaConfig.puntoVenta || 2);
  const cbteTipo = Number(datos.cbteTipo || 11); // 1: Factura A, 6: Factura B, 11: Factura C

  // Obtener último número oficial
  const { proximoNumero } = await getUltimoComprobante(ptoVta, cbteTipo);
  const cbteNro = Number(datos.cbteNro || proximoNumero);

  const fechaIso = datos.fecha || new Date().toISOString().slice(0, 10);
  const cbteFch = fechaIso.replace(/-/g, ""); // YYYYMMDD
  const concepto = Number(datos.concepto || 3); // 1: Productos, 2: Servicios, 3: Productos y Servicios

  const docTipo = Number(datos.docTipo || 99); // 80: CUIT, 96: DNI, 99: Final
  const docNro = Number(String(datos.docNro || 0).replace(/\D/g, ""));

  const impTotal = Number(Number(datos.impTotal || 0).toFixed(2));
  const impNeto = Number(Number(datos.impNeto ?? datos.impTotal ?? 0).toFixed(2));
  const impIva = Number(Number(datos.impIva || 0).toFixed(2));
  const impTotConc = 0;
  const impOpEx = 0;
  const impTrib = 0;

  let fchServXml = "";
  if (concepto === 2 || concepto === 3) {
    fchServXml = `
      <FchServDesde>${cbteFch}</FchServDesde>
      <FchServHasta>${cbteFch}</FchServHasta>
      <FchVtoPago>${cbteFch}</FchVtoPago>`;
  }

  let ivaXml = "";
  if (cbteTipo === 1 && impIva > 0) {
    ivaXml = `
      <Iva>
        <AlicIva>
          <Id>5</Id>
          <BaseImp>${impNeto}</BaseImp>
          <Importe>${impIva}</Importe>
        </AlicIva>
      </Iva>`;
  }

  const soap = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <FECAESolicitar xmlns="http://ar.gov.afip.dif.FEV1/">
      <Auth>
        <Token>${auth.token}</Token>
        <Sign>${auth.sign}</Sign>
        <Cuit>${cuitEmisor}</Cuit>
      </Auth>
      <FeCAEReq>
        <FeCabReq>
          <CantReg>1</CantReg>
          <PtoVta>${ptoVta}</PtoVta>
          <CbteTipo>${cbteTipo}</CbteTipo>
        </FeCabReq>
        <FeDetReq>
          <FECAEDetRequest>
            <Concepto>${concepto}</Concepto>
            <DocTipo>${docTipo}</DocTipo>
            <DocNro>${docNro}</DocNro>
            <CbteDesde>${cbteNro}</CbteDesde>
            <CbteHasta>${cbteNro}</CbteHasta>
            <CbteFch>${cbteFch}</CbteFch>
            <ImpTotal>${impTotal}</ImpTotal>
            <ImpTotConc>${impTotConc}</ImpTotConc>
            <ImpNeto>${impNeto}</ImpNeto>
            <ImpOpEx>${impOpEx}</ImpOpEx>
            <ImpTrib>${impTrib}</ImpTrib>
            <ImpIVA>${impIva}</ImpIVA>
            ${fchServXml}
            <MonId>PES</MonId>
            <MonCotiz>1</MonCotiz>
            ${ivaXml}
          </FECAEDetRequest>
        </FeDetReq>
      </FeCAEReq>
    </FECAESolicitar>
  </soap:Body>
</soap:Envelope>`;

  const resp = await postSoap(urls.wsfe, "http://ar.gov.afip.dif.FEV1/FECAESolicitar", soap);

  const resultadoMatch = resp.match(/<Resultado>(.*?)<\/Resultado>/);
  const caeMatch = resp.match(/<CAE>(.*?)<\/CAE>/);
  const caeVtoMatch = resp.match(/<CAEFchVto>(.*?)<\/CAEFchVto>/);

  if (!resultadoMatch || resultadoMatch[1] !== "A") {
    // Buscar mensajes de error
    const errMsgs = [];
    const matches = resp.matchAll(/<Msg>(.*?)<\/Msg>/g);
    for (const m of matches) errMsgs.push(m[1]);
    const obsMatches = resp.matchAll(/<Obs>[\s\S]*?<Msg>(.*?)<\/Msg>[\s\S]*?<\/Obs>/g);
    for (const m of obsMatches) errMsgs.push(m[1]);

    throw new Error(errMsgs.length ? errMsgs.join(" | ") : "Factura rechazada por ARCA.");
  }

  const cae = caeMatch ? caeMatch[1] : "";
  const caeVtoRaw = caeVtoMatch ? caeVtoMatch[1] : "";
  const vtoCae = caeVtoRaw.length === 8 ? `${caeVtoRaw.slice(0, 4)}-${caeVtoRaw.slice(4, 6)}-${caeVtoRaw.slice(6, 8)}` : "";

  // Generar URL oficial QR
  const qrPayload = {
    ver: 1,
    fecha: fechaIso,
    cuit: cuitEmisor,
    
