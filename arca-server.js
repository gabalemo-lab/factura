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
    try { 
