import express from "express"
import soap from "soap"
import cors from "cors"
import forge from "node-forge"
import { SignedXml } from "xml-crypto"
import { DOMParser } from "xmldom"

const app = express()

app.use(cors())
app.use(express.json({ limit: "20mb" }))

function extractCert(p12Base64, password) {

    const p12Der = forge.util.decode64(p12Base64)

    const p12Asn1 =
        forge.asn1.fromDer(p12Der)

    const p12 =
        forge.pkcs12.pkcs12FromAsn1(
            p12Asn1,
            password
        )

    let key
    let cert

    for (const safeContent of p12.safeContents) {

        for (const safeBag of safeContent.safeBags) {

            if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
                key = forge.pki.privateKeyToPem(
                    safeBag.key
                )
            }

            if (safeBag.type === forge.pki.oids.certBag) {
                cert = forge.pki.certificateToPem(
                    safeBag.cert
                )
            }
        }
    }

    return { key, cert }
}

function signXml(xml, key, cert) {

    const sig = new SignedXml()

    sig.addReference(
        "//*[local-name(.)='Invoice']"
    )

    sig.signingKey = key

    sig.keyInfoProvider = {
        getKeyInfo() {
            return `<X509Data><X509Certificate>${cert
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replace(/\n/g, "")
                }</X509Certificate></X509Data>`
        }
    }

    sig.computeSignature(xml)

    return sig.getSignedXml()
}

app.post("/dian/send", async (req, res) => {

    try {

        const {
            mode,
            environment,
            fileName,
            xml,
            testSetId,
            cert,
            certPassword
        } = req.body

        const { key, cert: certPem } =
            extractCert(cert, certPassword)

        const xmlFirmado =
            signXml(xml, key, certPem)

        const wsdl =
            environment === "habilitacion"
                ? "https://vpfe-hab.dian.gov.co/WcfDianCustomerServices.svc?wsdl"
                : "https://vpfe.dian.gov.co/WcfDianCustomerServices.svc?wsdl"

        const client =
            await soap.createClientAsync(wsdl)

        const security =
            new soap.WSSecurityCert(
                certPem,
                key,
                { hasTimeStamp: true }
            )

        client.setSecurity(security)

        let result

        if (mode === "test") {

            const [response] =
                await client.SendTestSetAsync({
                    fileName,
                    contentFile:
                        Buffer
                            .from(xmlFirmado)
                            .toString("base64"),
                    testSetId
                })

            result = response

        } else {

            const [response] =
                await client.SendBillSyncAsync({
                    fileName,
                    contentFile:
                        Buffer
                            .from(xmlFirmado)
                            .toString("base64")
                })

            result = response
        }

        res.json(result)

    } catch (error) {

        res.status(500).json({
            error: error.message
        })
    }
})

const PORT = process.env.PORT || 3000

app.listen(PORT)